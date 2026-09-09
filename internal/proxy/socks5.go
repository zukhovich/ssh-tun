package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
	"github.com/zukhovich/ssh-tun/internal/router"
)

var errRejected = errors.New("соединение отклонено правилами маршрутизации")

type SOCKS5OverSSH struct {
	cfg      *config.Config
	logger   *logger.Logger
	ssh      *SSHClient
	router   *router.Router
	listener net.Listener
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func NewSOCKS5OverSSH(cfg *config.Config, log *logger.Logger, sshClient *SSHClient, r *router.Router) (*SOCKS5OverSSH, error) {
	return &SOCKS5OverSSH{cfg: cfg, logger: log, ssh: sshClient, router: r, active: make(map[net.Conn]struct{})}, nil
}

func (s *SOCKS5OverSSH) Start() error {
	if s.cfg.SocksAddr == "" {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	listener, err := net.Listen("tcp", s.cfg.SocksAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf(i18n.Text("failed to start the SOCKS5 proxy: %w", "не удалось запустить SOCKS5-прокси: %w"), err)
	}
	s.listener = listener
	s.mu.Unlock()
	s.logger.Infof(i18n.Text("SOCKS5 proxy is listening on %s", "SOCKS5-прокси запущен на %s"), listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf(i18n.Text("failed to accept a SOCKS5 connection: %w", "ошибка приёма SOCKS5-соединения: %w"), err)
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return nil
		}
		s.active[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.active, conn)
				s.mu.Unlock()
				conn.Close()
			}()
			s.handleConnection(conn)
		}()
	}
}

func (s *SOCKS5OverSSH) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	for conn := range s.active {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *SOCKS5OverSSH) handleConnection(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	if err := s.handshake(conn); err != nil {
		return
	}
	target, host, err := s.readRequest(conn)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	dest, action, err := s.dialTarget(ctx, target, host)
	if err != nil {
		if errors.Is(err, errRejected) {
			_ = s.reply(conn, 0x02)
		} else {
			_ = s.reply(conn, 0x05)
		}
		return
	}
	defer dest.Close()
	if err := s.reply(conn, 0x00); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s.logger.Infof(i18n.Text("[SOCKS5] Connected to %s (rule: %s)", "[SOCKS5] Установлено соединение с %s (правило: %s)"), target, action)
	relay(conn, conn, dest, dest, s.logger)
}

func (s *SOCKS5OverSSH) handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("неподдерживаемая версия SOCKS: %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err
		}
	}
	_, _ = conn.Write([]byte{0x05, 0xff})
	return errors.New("клиент не предложил аутентификацию без пароля")
}

func (s *SOCKS5OverSSH) readRequest(conn net.Conn) (string, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != 0x05 || header[2] != 0x00 {
		return "", "", errors.New("неверный заголовок SOCKS5-запроса")
	}
	if header[1] != 0x01 {
		_ = s.reply(conn, 0x07)
		return "", "", fmt.Errorf("неподдерживаемая команда: %d", header[1])
	}
	var host string
	switch header[3] {
	case 0x01:
		value := make([]byte, 4)
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", "", err
		}
		host = net.IP(value).String()
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", "", err
		}
		if length[0] == 0 {
			return "", "", errors.New("пустое доменное имя")
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", "", err
		}
		host = string(value)
	case 0x04:
		value := make([]byte, 16)
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", "", err
		}
		host = net.IP(value).String()
	default:
		_ = s.reply(conn, 0x08)
		return "", "", fmt.Errorf("неподдерживаемый тип адреса: %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), host, nil
}

func (s *SOCKS5OverSSH) dialTarget(ctx context.Context, addr, host string) (net.Conn, router.Action, error) {
	action := router.ActionProxy
	if s.router != nil {
		action = s.router.Match(host)
	}
	switch action {
	case router.ActionReject:
		return nil, action, errRejected
	case router.ActionDirect:
		conn, err := (&net.Dialer{Timeout: s.cfg.Timeout}).DialContext(ctx, "tcp", addr)
		return conn, action, err
	default:
		conn, err := s.ssh.DialContext(ctx, "tcp", addr)
		return conn, action, err
	}
}

func (s *SOCKS5OverSSH) reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
