package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
	"github.com/zukhovich/ssh-tun/internal/proxy"
	"github.com/zukhovich/ssh-tun/internal/router"

	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TunService manages a TUN device and a userspace network stack.
type TunService struct {
	cfg         *config.Config
	logger      *logger.Logger
	ssh         *proxy.SSHClient
	dev         tun.Device
	stack       *stack.Stack
	endpoint    *channel.Endpoint
	tunIP       string
	prefix      int
	peerIP      string
	routes      []string
	global      bool
	router      *router.Router
	devName     string
	addedRoutes [][]string
	runCommand  func(...string) ([]byte, error)
	wg          sync.WaitGroup

	closeOnce sync.Once
}

// NewTunService creates a TUN service.
func NewTunService(cfg *config.Config, log *logger.Logger, sshClient *proxy.SSHClient, r *router.Router) (*TunService, error) {
	ip, ipNet, err := net.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("invalid TUN CIDR %s: %w"), cfg.TunCIDR, err)
	}
	tunIP := ip.To4()
	if tunIP == nil {
		return nil, fmt.Errorf(i18n.T("only IPv4 TUN addresses are supported: %s"), cfg.TunCIDR)
	}

	prefix, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf(i18n.T("invalid IPv4 mask in TUN CIDR: %s"), cfg.TunCIDR)
	}

	peerIP, err := ipAdd(tunIP, 1)
	if err != nil || !ipNet.Contains(peerIP) {
		return nil, fmt.Errorf(i18n.T("failed to select a peer address in subnet %s"), cfg.TunCIDR)
	}

	return &TunService{
		cfg:    cfg,
		logger: log,
		ssh:    sshClient,
		tunIP:  tunIP.String(),
		prefix: prefix,
		peerIP: peerIP.String(),
		routes: cfg.TunRoute,
		global: cfg.TunGlobal,
		router: r,
		runCommand: func(args ...string) ([]byte, error) {
			return exec.Command("ip", args...).CombinedOutput()
		},
	}, nil
}

// Start creates the TUN device and starts the network stack.
func (t *TunService) Start() error {
	devName := "ssh-tun"

	dev, err := tun.CreateTUN(devName, 1500)
	if err != nil {
		return fmt.Errorf(i18n.T("failed to create TUN device: %w"), err)
	}
	t.dev = dev
	cleanup := true
	defer func() {
		if cleanup {
			_ = t.Close()
		}
	}()

	realName, err := dev.Name()
	if err == nil {
		t.logger.Infof(i18n.T("[TUN] Device created: %s"), realName)
	} else {
		realName = "ssh-tun"
	}
	t.devName = realName

	if err := t.setupTunIP(realName); err != nil {
		dev.Close()
		return fmt.Errorf(i18n.T("failed to configure TUN IP address: %w"), err)
	}

	if err := t.checkRouteConflicts(); err != nil {
		return err
	}
	if err := t.initNetstack(); err != nil {
		return err
	}

	if t.global {
		if err := t.setupGlobalRoutes(realName); err != nil {
			return fmt.Errorf(i18n.T("failed to configure global routes: %w"), err)
		}
	} else if len(t.routes) > 0 {
		if err := t.setupRoutes(realName); err != nil {
			return fmt.Errorf(i18n.T("failed to configure routes: %w"), err)
		}
	}

	for _, sas := range t.cfg.SubnetAliases {
		cidr := sas.Src.String()
		t.logger.Infof(i18n.T("[TUN] Adding subnet alias route: %s -> TUN"), cidr)
		if err := t.addDeviceRoute(cidr, realName); err != nil {
			return fmt.Errorf(i18n.T("failed to add NAT route %s: %w"), cidr, err)
		}
	}

	t.wg.Add(2)
	go t.pumpTunToStack()
	go t.pumpStackToTun()

	t.logger.Infof(i18n.T("[TUN] Mode started: IP address %s, peer address %s"), t.tunIP, t.peerIP)

	cleanup = false
	return nil
}

// Close stops the service and removes its routes.
func (t *TunService) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		if t.dev != nil {
			t.dev.Close()
		}
		if t.stack != nil {
			t.stack.Close()
		}
		t.wg.Wait()
		for i := len(t.addedRoutes) - 1; i >= 0; i-- {
			args := append([]string{"route", "del"}, t.addedRoutes[i]...)
			if output, err := t.runCommand(args...); err != nil && !strings.Contains(string(output), "No such process") {
				closeErr = fmt.Errorf(i18n.T("failed to remove route %v: %s: %w"), t.addedRoutes[i], strings.TrimSpace(string(output)), err)
			}
		}
	})
	return closeErr
}

// initNetstack initializes the gVisor network stack.
func (t *TunService) initNetstack() error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	e := channel.New(256, 1500, "")
	t.endpoint = e

	if err := s.CreateNIC(1, e); err != nil {
		return fmt.Errorf(i18n.T("failed to create NIC: %v"), err)
	}

	parsedIP := net.ParseIP(t.tunIP)
	addr := tcpip.AddrFromSlice(parsedIP.To4())
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: t.prefix,
		},
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf(i18n.T("failed to add protocol address: %v"), err)
	}

	if err := s.SetPromiscuousMode(1, true); err != nil {
		return fmt.Errorf(i18n.T("failed to enable promiscuous mode: %v"), err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		return fmt.Errorf(i18n.T("failed to enable address spoofing: %v"), err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
	})

	tcpHandler := tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		destIP := id.LocalAddress.String()
		destPort := id.LocalPort

		targetHost := destIP
		parsedDestIP := net.ParseIP(destIP)

		if parsedDestIP != nil {
			parsedDestIP = parsedDestIP.To4()
			if parsedDestIP != nil {
				for _, rule := range t.cfg.SubnetAliases {
					if rule.Src.Contains(parsedDestIP) {
						offset, _ := ipSub(parsedDestIP, rule.Src.IP)
						realTargetIP, _ := ipAdd(rule.Dst.IP, offset)
						targetHost = realTargetIP.String()
						t.logger.Infof(i18n.T("[TUN] NAT rule matched: %s -> %s (offset: %d)"), destIP, targetHost, offset)
						break
					}
				}
			}
		}

		targetAddr := fmt.Sprintf("%s:%d", targetHost, destPort)
		t.logger.Infof(i18n.T("[TUN] TCP request received -> %s (original target: %s:%d)"), targetAddr, destIP, destPort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			t.logger.Errorf(i18n.T("Failed to create a TCP endpoint: %v"), err)
			r.Complete(true)
			return
		}
		r.Complete(false)
		localConn := gonet.NewTCPConn(&wq, ep)
		go t.handleTCPForward(localConn, targetAddr)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	udpHandler := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort != 53 {
			return false
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			t.logger.Errorf(i18n.T("[TUN] Failed to create a UDP endpoint: %v"), err)
			return true
		}

		localConn := gonet.NewUDPConn(&wq, ep)
		go t.handleUDPForward(localConn, id.LocalAddress.String(), id.LocalPort)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)

	t.stack = s
	return nil
}

func (t *TunService) handleUDPForward(conn *gonet.UDPConn, targetIP string, targetPort uint16) {
	defer conn.Close()
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return
	}
	dnsQuery := buf[:n]

	tcpQuery := make([]byte, 2+len(dnsQuery))
	binary.BigEndian.PutUint16(tcpQuery[0:2], uint16(len(dnsQuery)))
	copy(tcpQuery[2:], dnsQuery)

	targetAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)
	if t.router != nil && t.router.Match(targetIP) == router.ActionReject {
		return
	}
	remoteConn, err := t.dial(targetIP, targetAddr)
	if err != nil {
		t.logger.Warnf(i18n.T("[TUN] Failed to connect to remote DNS %s: %v"), targetAddr, err)
		return
	}
	defer remoteConn.Close()
	_ = remoteConn.SetDeadline(time.Now().Add(t.cfg.Timeout))

	if _, err := remoteConn.Write(tcpQuery); err != nil {
		return
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(remoteConn, lenBuf); err != nil {
		return
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(remoteConn, respBuf); err != nil {
		return
	}
	conn.Write(respBuf)
}

func (t *TunService) handleTCPForward(localConn net.Conn, targetAddr string) {
	defer localConn.Close()
	host, _, _ := net.SplitHostPort(targetAddr)
	if t.router != nil && t.router.Match(host) == router.ActionReject {
		return
	}
	remoteConn, err := t.dial(host, targetAddr)
	if err != nil {
		t.logger.Warnf(i18n.T("[TUN] Failed to connect to target %s: %v"), targetAddr, err)
		return
	}
	defer remoteConn.Close()
	t.logger.Infof(i18n.T("[TUN] Tunnel established: %s <-> %s"), localConn.RemoteAddr(), targetAddr)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
		if c, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
		if c, ok := localConn.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()
	wg.Wait()
}

func (t *TunService) dial(host, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
	defer cancel()
	if t.router != nil && t.router.Match(host) == router.ActionDirect {
		return (&net.Dialer{Timeout: t.cfg.Timeout}).DialContext(ctx, "tcp", addr)
	}
	return t.ssh.DialContext(ctx, "tcp", addr)
}

func (t *TunService) pumpTunToStack() {
	defer t.wg.Done()
	const batchSize = 1
	bufs := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, 1600)
	}
	sizes := make([]int, batchSize)
	offset := 4

	for {
		n, err := t.dev.Read(bufs, sizes, offset)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") || strings.Contains(err.Error(), "closed network connection") {
				return
			}
			t.logger.Errorf(i18n.T("[TUN] Device read error: %v"), err)
			return
		}

		for i := 0; i < n; i++ {
			size := sizes[i]
			data := bufs[i][offset : offset+size]
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			t.endpoint.InjectInbound(header.IPv4ProtocolNumber, packetBuf)
		}
	}
}

func (t *TunService) pumpStackToTun() {
	defer t.wg.Done()
	offset := 4

	for {
		pkt := t.endpoint.Read()
		if pkt == nil {
			return
		}
		views := pkt.ToView().ToSlice()

		buf := make([]byte, offset+len(views))
		copy(buf[offset:], views)
		pkt.DecRef()

		_, err := t.dev.Write([][]byte{buf}, offset)
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") || strings.Contains(err.Error(), "closed network connection") {
				return
			}
			t.logger.Errorf(i18n.T("[TUN] Device write error: %v"), err)
			return
		}
	}
}

func (t *TunService) setupTunIP(devName string) error {
	t.logger.Infof(i18n.T("[TUN] Configuring IP address for %s: %s"), devName, t.tunIP)

	output, err := t.runCommand("addr", "add", fmt.Sprintf("%s/%d", t.tunIP, t.prefix), "dev", devName)
	if err != nil {
		return fmt.Errorf(i18n.T("ip addr add: %s: %w"), strings.TrimSpace(string(output)), err)
	}
	output, err = t.runCommand("link", "set", devName, "up")
	if err != nil {
		return fmt.Errorf(i18n.T("ip link set: %s: %w"), strings.TrimSpace(string(output)), err)
	}
	return nil
}

func (t *TunService) setupRoutes(devName string) error {
	t.logger.Infof(i18n.T("[TUN] Configuring routes: %v"), t.routes)
	for _, cidr := range t.routes {
		if err := t.addDeviceRoute(cidr, devName); err != nil {
			return fmt.Errorf(i18n.T("failed to add route %s: %w"), cidr, err)
		}
	}
	return nil
}

func (t *TunService) setupGlobalRoutes(devName string) error {
	t.logger.Info(i18n.T("[TUN] Configuring global routes..."))
	gateway, err := t.getDefaultGateway()
	if err != nil {
		return fmt.Errorf(i18n.T("failed to get the default gateway: %w"), err)
	}
	t.logger.Infof(i18n.T("[TUN] Default gateway detected: %s"), gateway)

	sshHost := t.cfg.SSHServer
	if host, _, err := net.SplitHostPort(sshHost); err == nil {
		sshHost = host
	}

	sshIPs, err := net.LookupIP(sshHost)
	if err != nil {
		return fmt.Errorf(i18n.T("failed to resolve the SSH server IP address: %w"), err)
	}
	if len(sshIPs) == 0 {
		return errors.New(i18n.T("SSH server IP address was not found"))
	}
	var targetSSHIP string
	for _, ip := range sshIPs {
		if ipv4 := ip.To4(); ipv4 != nil {
			targetSSHIP = ipv4.String()
			break
		}
	}
	if targetSSHIP == "" {
		return errors.New(i18n.T("SSH server has no IPv4 address"))
	}
	t.logger.Infof(i18n.T("[TUN] Adding bypass route for SSH server %s (%s) via %s"), sshHost, targetSSHIP, gateway)

	if err := t.addGatewayRoute(targetSSHIP, gateway); err != nil {
		return fmt.Errorf(i18n.T("failed to add SSH bypass route: %w"), err)
	}

	t.logger.Info(i18n.T("[TUN] Adding global routes (0.0.0.0/1, 128.0.0.0/1)..."))
	if err := t.addDeviceRoute("0.0.0.0/1", devName); err != nil {
		return fmt.Errorf(i18n.T("failed to add route 0.0.0.0/1: %w"), err)
	}
	if err := t.addDeviceRoute("128.0.0.0/1", devName); err != nil {
		return fmt.Errorf(i18n.T("failed to add route 128.0.0.0/1: %w"), err)
	}
	return nil
}

func (t *TunService) addDeviceRoute(target, devName string) error {
	return t.addRoute([]string{target, "dev", devName})
}

func (t *TunService) addGatewayRoute(target, gateway string) error {
	return t.addRoute([]string{target, "via", gateway})
}

func (t *TunService) addRoute(routeArgs []string) error {
	args := append([]string{"route", "add"}, routeArgs...)
	if output, err := t.runCommand(args...); err != nil {
		outStr := string(output)
		if strings.Contains(outStr, "File exists") || strings.Contains(outStr, "exist") {
			t.logger.Warnf(i18n.T("[TUN] Route already exists; ignoring: %s"), outStr)
			return nil
		}
		return fmt.Errorf(i18n.T("ip %s: %s: %w"), strings.Join(args, " "), strings.TrimSpace(outStr), err)
	}
	t.addedRoutes = append(t.addedRoutes, append([]string(nil), routeArgs...))
	return nil
}

func (t *TunService) getDefaultGateway() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) >= 3 && parts[0] == "default" && parts[1] == "via" {
		return parts[2], nil
	}
	return "", errors.New(i18n.T("default gateway not found"))
}

func (t *TunService) checkRouteConflicts() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.logger.Warnf(i18n.T("[TUN] Failed to list network interfaces; skipping conflict checks: %v"), err)
		return nil
	}

	sshHost := t.cfg.SSHServer
	if host, _, err := net.SplitHostPort(sshHost); err == nil {
		sshHost = host
	}
	sshIPs, _ := net.LookupIP(sshHost)

	checkConflict := func(targetCIDR string) error {
		_, network, err := net.ParseCIDR(targetCIDR)
		if err != nil {
			return nil
		}

		for _, sshIP := range sshIPs {
			sshIPV4 := sshIP.To4()
			if sshIPV4 != nil && network.Contains(sshIPV4) {
				return fmt.Errorf(i18n.T("SSH server IP %s is inside route subnet %s"), sshIPV4, targetCIDR)
			}
		}

		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				ip = ip.To4()
				if ip == nil || ip.IsLoopback() {
					continue
				}

				if network.Contains(ip) {
					t.logger.Warnf(i18n.T("[TUN] Route conflict warning: requested route %s contains IP %s of interface %s. Traffic may use the physical interface."), targetCIDR, ip.String(), iface.Name)
				}
			}
		}
		return nil
	}

	for _, route := range t.routes {
		if err := checkConflict(route); err != nil {
			return err
		}
	}
	for _, alias := range t.cfg.SubnetAliases {
		if err := checkConflict(alias.Src.String()); err != nil {
			return err
		}
	}
	return nil
}

func ipToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, errors.New(i18n.T("expected an IPv4 address"))
	}
	return binary.BigEndian.Uint32(ip), nil
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func ipAdd(ip net.IP, offset uint32) (net.IP, error) {
	val, err := ipToUint32(ip)
	if err != nil || offset > ^uint32(0)-val {
		return nil, errors.New(i18n.T("IPv4 address overflow"))
	}
	return uint32ToIP(val + offset), nil
}

func ipSub(a, b net.IP) (uint32, error) {
	av, err := ipToUint32(a)
	if err != nil {
		return 0, err
	}
	bv, err := ipToUint32(b)
	if err != nil {
		return 0, err
	}
	if av < bv {
		return 0, errors.New(i18n.T("negative IPv4 address offset"))
	}
	return av - bv, nil
}
