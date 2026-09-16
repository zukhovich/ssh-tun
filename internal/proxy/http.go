package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
	"github.com/zukhovich/ssh-tun/internal/router"
)

const maxHTTPHeaderBytes = 1 << 20

type HTTPOverSSH struct {
	cfg       *config.Config
	ssh       *SSHClient
	logger    *logger.Logger
	server    *http.Server
	router    *router.Router
	transport *http.Transport

	mu          sync.Mutex
	listener    net.Listener
	activeConns map[net.Conn]struct{}
	closed      bool
	started     chan struct{}
	startErr    error
	startOnce   sync.Once
}

func NewHTTPOverSSH(cfg *config.Config, log *logger.Logger, sshClient *SSHClient, r *router.Router) (*HTTPOverSSH, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	p := &HTTPOverSSH{
		cfg:         cfg,
		ssh:         sshClient,
		logger:      log,
		router:      r,
		activeConns: make(map[net.Conn]struct{}),
		started:     make(chan struct{}),
	}
	p.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       90 * time.Second,
	}
	p.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           http.HandlerFunc(p.handleHTTP),
		ReadHeaderTimeout: cfg.Timeout,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}
	return p, nil
}

// Ready waits until the listener has opened or startup has failed.
func (p *HTTPOverSSH) Ready() error {
	<-p.started
	return p.startErr
}

func (p *HTTPOverSSH) signalStarted(err error) {
	p.startOnce.Do(func() {
		p.startErr = err
		close(p.started)
	})
}

// Start opens the listener before serving so startup errors are synchronous.
func (p *HTTPOverSSH) Start() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.signalStarted(net.ErrClosed)
		return net.ErrClosed
	}
	listener, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		p.mu.Unlock()
		err = fmt.Errorf(i18n.Text("failed to start the HTTP proxy: %w", "не удалось запустить HTTP-прокси: %w"), err)
		p.signalStarted(err)
		return err
	}
	p.listener = listener
	p.mu.Unlock()
	p.signalStarted(nil)
	p.logger.Infof(i18n.Text("HTTP/HTTPS proxy is listening on %s", "HTTP/HTTPS-прокси запущен на %s"), listener.Addr())
	err = p.server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (p *HTTPOverSSH) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}
	p.handlePlainHTTP(w, req)
}

func (p *HTTPOverSSH) action(host string) router.Action {
	if p.router == nil {
		return router.ActionProxy
	}
	return p.router.Match(host)
}

func (p *HTTPOverSSH) handlePlainHTTP(w http.ResponseWriter, req *http.Request) {
	if !req.URL.IsAbs() {
		http.Error(w, "Требуется абсолютный URL", http.StatusBadRequest)
		return
	}
	action := p.action(req.Host)
	if action == router.ActionReject {
		p.logger.Infof(i18n.Text("Request rejected by a routing rule: %s", "Запрос отклонён правилом маршрутизации: %s"), req.Host)
		http.Error(w, "Запрос отклонён правилами маршрутизации", http.StatusForbidden)
		return
	}
	if action == router.ActionDirect {
		p.handleDirect(w, req)
		return
	}

	target := req.URL.Host
	if p.cfg.HTTPUpstream != "" {
		target = p.cfg.HTTPUpstream
	}
	target = addressWithDefaultPort(target, "80")
	ctx, cancel := context.WithTimeout(req.Context(), p.cfg.Timeout)
	defer cancel()
	if p.ssh == nil {
		http.Error(w, "SSH-клиент не готов", http.StatusBadGateway)
		return
	}
	conn, err := p.ssh.DialContext(ctx, "tcp", target)
	if err != nil {
		http.Error(w, "Не удалось подключиться к цели через SSH", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)
	if err := outReq.Write(conn); err != nil {
		http.Error(w, "Ошибка отправки запроса", http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), outReq)
	if err != nil {
		http.Error(w, "Ошибка чтения ответа", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_ = conn.SetDeadline(time.Time{})
	copyResponse(w, resp)
}

func (p *HTTPOverSSH) handleDirect(w http.ResponseWriter, req *http.Request) {
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Не удалось выполнить прямой запрос", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	removeHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPOverSSH) handleConnect(w http.ResponseWriter, req *http.Request) {
	action := p.action(req.Host)
	if action == router.ActionReject {
		http.Error(w, "Соединение отклонено правилами маршрутизации", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Перехват соединения не поддерживается", http.StatusInternalServerError)
		return
	}
	target := addressWithDefaultPort(req.Host, "443")
	ctx, cancel := context.WithTimeout(req.Context(), p.cfg.Timeout)
	defer cancel()
	var upstream net.Conn
	var err error
	if action == router.ActionDirect {
		upstream, err = (&net.Dialer{Timeout: p.cfg.Timeout}).DialContext(ctx, "tcp", target)
	} else {
		if p.ssh == nil {
			http.Error(w, "SSH-клиент не готов", http.StatusBadGateway)
			return
		}
		upstream, err = p.ssh.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		http.Error(w, "Не удалось подключиться к цели", http.StatusBadGateway)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	p.track(client, true)
	p.track(upstream, true)
	defer func() {
		p.track(client, false)
		p.track(upstream, false)
		client.Close()
		upstream.Close()
	}()
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	relay(client, rw.Reader, upstream, upstream, p.logger)
}

func relay(left net.Conn, leftReader io.Reader, right net.Conn, rightReader io.Reader, log *logger.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil && !isConnectionClosed(err) {
			log.Debugf(i18n.Text("Data transfer error: %v", "Ошибка передачи данных: %v"), err)
		}
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyOne(right, leftReader)
	go copyOne(left, rightReader)
	wg.Wait()
}

func (p *HTTPOverSSH) track(conn net.Conn, add bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if add {
		p.activeConns[conn] = struct{}{}
	} else {
		delete(p.activeConns, conn)
	}
}

func (p *HTTPOverSSH) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for conn := range p.activeConns {
		_ = conn.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.server.Shutdown(ctx); err != nil {
		return errors.Join(err, p.server.Close())
	}
	return nil
}

func addressWithDefaultPort(address, port string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	return net.JoinHostPort(strings.Trim(address, "[]"), port)
}

func removeHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func isConnectionClosed(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "broken pipe")
}
