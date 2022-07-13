// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	rate "golang.org/x/time/rate"

	"github.com/technicianted/whip/pkg/logging"
	protov1 "github.com/technicianted/whip/pkg/proto/v1"
	"github.com/technicianted/whip/pkg/server/metrics"
	"github.com/technicianted/whip/pkg/types"

	//lint:ignore SA1019 convenience of working with streams
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/uuid"
	bloque "github.com/technicianted/bloque"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// max rate of pinging registered clients
	pingMaxRate  = time.Millisecond
	pingInterval = 20 * time.Second
)

type remoteHost struct {
	hostname               string
	domain                 string
	ports                  []uint32
	peer                   *peer.Peer
	stream                 protov1.Whip_RegisterServer
	connectionRequestQueue *bloque.Bloque
	tls                    bool
}

type connectionItem struct {
	remoteHost *remoteHost
	conn       net.Conn
	err        error
}

type remoteError struct {
	Err error
}

var _ types.Dialer = &Service{}

// Service implements the whip control grpc service and types.DialContext for users to
// request reverse tcp connections.
// Although the service does not deal with setting up tls, it does perform tls verification
// if the incoming Register grpc is over tls.
// Verification is based on the hostname.domain in the incoming Register message. It needs
// to match the certificate DNS entries or SAN. Wild card certificates can be used.
//
// In the background, the service continuously pings remove clients over the control channel
// and emits relevant latency metrics.
type Service struct {
	protov1.WhipServer

	externalTCPHost string
	externalTCPPort int

	remoteHostsByName              map[string]map[string]*remoteHost
	remoteHostsByPeer              map[*peer.Peer]*remoteHost
	remoteHostsByPendingConnection map[string]*remoteHost
	resolverWaitingChans           []chan interface{}
	pingerTimer                    *time.Timer
	pingChan                       chan protov1.Whip_RegisterServer
	pingerTerminatedChan           chan interface{}
	mutex                          sync.Mutex

	tcpListener net.Listener
	stoppedChan chan interface{}
	stopping    bool
}

// NewService creates a new service instance. For remote clients, externalTCPHost is the host
// that remote clients can use to reach the service with externalTCPPort. It uses tcpListener to listen
// for remote tcp connection requests.
func NewService(externalTCPHost string, externalTCPPort int, tcpListner net.Listener, logger logging.TraceLogger) (*Service, error) {
	s := &Service{
		externalTCPHost:                externalTCPHost,
		externalTCPPort:                externalTCPPort,
		tcpListener:                    tcpListner,
		remoteHostsByName:              make(map[string]map[string]*remoteHost),
		remoteHostsByPeer:              make(map[*peer.Peer]*remoteHost),
		remoteHostsByPendingConnection: make(map[string]*remoteHost),
		resolverWaitingChans:           make([]chan interface{}, 0),
	}
	if err := s.startTcpServer(logger); err != nil {
		return nil, err
	}

	return s, nil
}

// Start start the service by starting the background workers. The implementation does not
// deal with the grpc server. Callers would need to register it before calling Start.
func (s *Service) Start(logger logging.TraceLogger) error {
	s.stoppedChan = make(chan interface{})

	s.pingChan = make(chan protov1.Whip_RegisterServer)
	go s.pingWorker(logger)

	logger.Infof("starting periodic client pings at %v interval", pingInterval)
	s.pingerTimer = time.NewTimer(pingInterval)
	s.pingerTerminatedChan = make(chan interface{})
	go s.pinger(logger)

	return nil
}

// Stop stops all background processes for the service but does not terminate the
// already established tcp connections.
func (s *Service) Stop(logger logging.TraceLogger) error {
	s.stopping = true
	close(s.stoppedChan)

	logger.Debugf("stopping pinger")
	if s.pingerTimer != nil {
		s.pingerTimer.Stop()
	}
	if s.pingerTerminatedChan != nil {
		<-s.pingerTerminatedChan
	}
	logger.Debugf("pinger stopped")

	if s.pingChan != nil {
		close(s.pingChan)
	}

	return nil
}

// Register implements the grpc service.
func (s *Service) Register(stream protov1.Whip_RegisterServer) error {
	logger := logging.NewTraceLogger("service")
	ctx := stream.Context()
	remotePeer, ok := peer.FromContext(ctx)
	if !ok {
		logger.Errorf("new request from unknown peer")
		return status.Errorf(codes.FailedPrecondition, "unable to obtain remote peer")
	}

	logger.Tracef("new request: %v", remotePeer.Addr)

	var err error
	for err == nil {
		var msg *protov1.RequestStream
		msg, err = stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			logger.Debugf("request finished due to receive error: %v", err)
			break
		}

		switch req := msg.Stream.(type) {
		case *protov1.RequestStream_Register:
			if err = s.handleRegister(ctx, remotePeer, stream, req.Register, logger); err != nil {
				logger.Errorf("failed to handle register: %v", err)
				break
			}

		case *protov1.RequestStream_ConnectFailed:
			if err = s.handleConnectFailed(ctx, req.ConnectFailed, logger); err != nil {
				logger.Errorf("failed to handle connection failure: %v", err)
				break
			}

		case *protov1.RequestStream_Pong:
			s.handlePong(ctx, remotePeer, req.Pong, logger)
		}
	}

	logger.Tracef("call terminated: %v", err)

	s.handleRequestCleanup(remotePeer, logger)

	return err
}

// DialContext implements types.Dialer.
func (s *Service) DialContext(ctx context.Context, network, address string, logger logging.TraceLogger, opts ...types.DialOption) (net.Conn, error) {
	logger = logging.NewTraceLoggerFromLogger("service", logger)
	options := newDialOptions(opts)
	logger.Tracef("dialing %s:%s, options: %+v", network, address, options)

	totalLatencyTime := time.Now()

	if network != "tcp" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	addr, portName, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portName, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port %s: %v", portName, err)
	}

	resolveLatencyTime := time.Now()
	remotes, err := s.resolve(ctx, addr, options.waitForResolve, logger)
	if err != nil {
		return nil, err
	}
	remote := remotes[0]
	metrics.TCPConnectionLatency.WithLabelValues(remote.domain, metrics.OpTCPConnectionResolve).Observe(time.Since(resolveLatencyTime).Seconds())

	logger.Infof("resolved %s to %d hosts", addr, len(remotes))

	if len(remotes) > 1 {
		remote = remotes[rand.Intn(len(remotes)-1)]
	}
	logger.Infof("selected remote: %v", remote)

	portFound := false
	for _, remotePort := range remote.ports {
		if int(remotePort) == int(port) {
			portFound = true
			break
		}
	}
	if !portFound {
		return nil, &net.OpError{
			Op:  "connect",
			Err: fmt.Errorf("connection refused"),
		}
	}

	connectionID := uuid.New().String()
	logger.Infof("sending connection request %s to peer: %v", connectionID, remote)
	err = remote.stream.Send(&protov1.ResponseStream{
		Stream: &protov1.ResponseStream_Connect{
			Connect: &protov1.Connect{
				ConnectionID: connectionID,
				Host:         s.externalTCPHost,
				Port:         uint32(s.externalTCPPort),
				LocalPort:    uint32(port),
			},
		},
	})
	if err != nil {
		return nil, &net.OpError{
			Op:  "connect",
			Err: fmt.Errorf("failed to send connect request: %v", err),
		}
	}

	s.mutex.Lock()
	s.remoteHostsByPendingConnection[connectionID] = remote
	s.mutex.Unlock()

	item, err := remote.connectionRequestQueue.Pop(ctx)
	if err != nil {
		return nil, err
	}

	connEntry := item.(*connectionItem)
	if connEntry.err != nil {
		return nil, newRemoteError(connEntry.err)
	}

	metrics.TCPConnectionLatency.WithLabelValues(remote.domain, "").Observe(time.Since(totalLatencyTime).Seconds())
	return metrics.NewInstrumentedConn(
			connEntry.conn,
			connEntry.remoteHost.domain,
			int(port),
			logger),
		nil
}

func (s *Service) resolve(ctx context.Context, hostname string, wait bool, logger logging.TraceLogger) (remotes []*remoteHost, err error) {
	logger.Tracef("resolving %s, wait: %v", hostname, wait)

	for {
		s.mutex.Lock()
		hosts, ok := s.remoteHostsByName[hostname]
		if ok {
			for _, remote := range hosts {
				remotes = append(remotes, remote)
			}
			s.mutex.Unlock()
			return
		}

		parts := strings.Split(hostname, ".")
		if len(parts) > 1 {
			host := parts[0]
			domain := strings.Join(parts[1:], ".")
			logger.Tracef("attempting fqdn: host: %s, domain: %s", host, domain)
			hosts, ok = s.remoteHostsByName[domain]
			if ok {
				if remote, ok := hosts[host]; ok {
					remotes = append(remotes, remote)
					s.mutex.Unlock()
					return
				}
			}
		}

		// attempts failed
		if !wait {
			s.mutex.Unlock()
			err = &net.DNSError{
				Err:        "host does not exist",
				Name:       hostname,
				IsNotFound: true,
			}
			return
		}

		logger.Tracef("waiting for host to be available")
		waitChan := make(chan interface{})
		s.resolverWaitingChans = append(s.resolverWaitingChans, waitChan)
		s.mutex.Unlock()
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		case <-waitChan:
		}
	}
}

func (s *Service) handleRegister(ctx context.Context, remotePeer *peer.Peer, stream protov1.Whip_RegisterServer, msg *protov1.Register, logger logging.TraceLogger) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logger.Infof("registering new remote host: %v", msg)
	if msg.Hostname == "" {
		return status.Errorf(codes.InvalidArgument, "empty hostname")
	}
	if msg.Domain == "" {
		return status.Errorf(codes.InvalidArgument, "empty domain")
	}
	if len(msg.Ports) == 0 {
		return status.Errorf(codes.InvalidArgument, "no published ports")
	}

	fqdnHost := msg.Hostname + "." + msg.Domain
	isTLS, err := s.authenticateRegistration(remotePeer, fqdnHost, logger)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, err.Error())
	}

	if _, ok := s.remoteHostsByName[msg.Domain]; !ok {
		s.remoteHostsByName[msg.Domain] = map[string]*remoteHost{}
	}
	if _, ok := s.remoteHostsByName[msg.Domain][msg.Hostname]; ok {
		logger.Warnf("overwriting existing registration for %s", fqdnHost)
	}
	remote := &remoteHost{
		hostname:               msg.Hostname,
		domain:                 msg.Domain,
		ports:                  msg.Ports,
		stream:                 stream,
		peer:                   remotePeer,
		connectionRequestQueue: bloque.New(),
		tls:                    isTLS,
	}
	s.remoteHostsByName[msg.Domain][msg.Hostname] = remote
	s.remoteHostsByPeer[remotePeer] = remote

	// notify any pending resolver that we have updates
	for _, c := range s.resolverWaitingChans {
		close(c)
	}
	s.resolverWaitingChans = make([]chan interface{}, 0)

	metrics.ActiveRegistrations.WithLabelValues(msg.Domain).Set(float64(len(s.remoteHostsByName)))

	return nil
}

func (s *Service) authenticateRegistration(remotePeer *peer.Peer, fqdnHost string, logger logging.TraceLogger) (bool, error) {
	tlsInfo, ok := remotePeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return false, nil
	}

	logger.Debugf("tls enabled, validating domain name %s", fqdnHost)
	if len(tlsInfo.State.PeerCertificates) == 0 {
		logger.Infof("no peer certificate found, authorizing")
		return false, nil
	}

	cert := tlsInfo.State.PeerCertificates[0]
	return true, cert.VerifyHostname(fqdnHost)
}

func (s *Service) handleConnectFailed(ctx context.Context, msg *protov1.ConnectFailed, logger logging.TraceLogger) error {
	logger.Infof("received connection failure message: %v", msg)

	s.mutex.Lock()

	remote, ok := s.remoteHostsByPendingConnection[msg.ConnectionID]
	if !ok {
		logger.Errorf("connection ID not found")
		s.mutex.Unlock()
		return nil
	}
	delete(s.remoteHostsByPendingConnection, msg.ConnectionID)

	s.mutex.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	err := remote.connectionRequestQueue.Push(ctx, &connectionItem{
		remoteHost: remote,
		err:        fmt.Errorf(msg.ErrorMessage),
	})
	if err != nil {
		logger.Errorf("failed to enqueue error connection: %v", err)
		return nil
	}

	return nil
}

func (s *Service) handleRequestCleanup(remotePeer *peer.Peer, logger logging.TraceLogger) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logger.Infof("unregistering peer: %v", remotePeer.Addr)

	remoteHost, ok := s.remoteHostsByPeer[remotePeer]
	if !ok {
		logger.Warnf("failed to get registration information for peer")
		return
	}
	delete(s.remoteHostsByPeer, remotePeer)
	delete(s.remoteHostsByName[remoteHost.domain], remoteHost.hostname)
	if len(s.remoteHostsByName[remoteHost.domain]) == 0 {
		delete(s.remoteHostsByName, remoteHost.domain)
	}

	metrics.ActiveRegistrations.WithLabelValues(remoteHost.domain).Set(float64(len(s.remoteHostsByName)))
}

func (s *Service) handlePong(ctx context.Context, remotePeer *peer.Peer, msg *protov1.Pong, logger logging.TraceLogger) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	latency := time.Since(msg.PingTimestamp.AsTime())

	logger.Tracef("pong from peer: %v, latency: %v", remotePeer.Addr, latency)

	remoteHost, ok := s.remoteHostsByPeer[remotePeer]
	if !ok {
		logger.Warnf("failed to get registration information for peer")
		return
	}

	metrics.ClientRoundTripLatency.WithLabelValues(remoteHost.domain).Observe(latency.Seconds())
}

func (s *Service) startTcpServer(logger logging.TraceLogger) error {
	logger = logging.NewTraceLoggerFromLogger("tcpserver", logger)

	logger.Infof("starting tcp server on %s", s.tcpListener.Addr())

	go func() {
		for {
			conn, err := s.tcpListener.Accept()
			if err != nil {
				if !s.stopping {
					logger.Errorf("failed to accept new connection: %v", err)
				}
				break
			}

			s.handleNewTCPConnection(conn, logger)
		}
		logger.Infof("tcp server shutdown")
	}()

	return nil
}

//lint:ignore SA4009 the argument is not really used but kept as convention
func (s *Service) handleNewTCPConnection(conn net.Conn, logger logging.TraceLogger) {
	logger = logging.NewTraceLogger("tcpconn")

	logger.Debugf("new connection from: %v", conn.RemoteAddr())

	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()

	preamble := &protov1.ConnectionPreamble{}
	if err := jsonpb.Unmarshal(conn, preamble); err != nil {
		logger.Debugf("failed to get preamble: %v", err)
		return
	}

	logger.Infof("new connection preamble: %v", preamble)

	s.mutex.Lock()
	remote, ok := s.remoteHostsByPendingConnection[preamble.ConnectionID]
	if !ok {
		logger.Errorf("connection ID not found")
		s.mutex.Unlock()
		return
	}
	delete(s.remoteHostsByPendingConnection, preamble.ConnectionID)
	s.mutex.Unlock()

	if err := s.authorizeTCPConnection(conn, remote, logger); err != nil {
		logger.Errorf("tcp connection auth failed: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := remote.connectionRequestQueue.Push(ctx, &connectionItem{
		remoteHost: remote,
		conn:       conn,
	})
	if err != nil {
		logger.Errorf("failed to enqueue new connection: %v", err)
		return
	}

	success = true
}

func (s *Service) authorizeTCPConnection(conn net.Conn, remote *remoteHost, logger logging.TraceLogger) error {
	fqdnHost := remote.hostname + "." + remote.domain
	logger.Infof("authorizing tcp connection with fqdn %s", fqdnHost)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		if remote.tls {
			return fmt.Errorf("expected tls")
		}
		logger.Tracef("allowing plain text tcp connection")
		return nil
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("client did not send tls certificates")
	}
	cert := certs[0]
	return cert.VerifyHostname(fqdnHost)
}

func (s *Service) pinger(logger logging.TraceLogger) {
	logger = logging.NewTraceLoggerFromLogger("pinger", logger)
	for !s.stopping {
		select {
		case <-s.pingerTimer.C:
		case <-s.stoppedChan:
			continue
		}

		s.pingerTimer.Reset(pingInterval)

		s.mutex.Lock()

		streams := []protov1.Whip_RegisterServer{}
		for _, host := range s.remoteHostsByPeer {
			streams = append(streams, host.stream)
		}
		s.mutex.Unlock()

		if len(streams) == 0 {
			continue
		}

		logger.Tracef("queuing %d pings", len(streams))
		for _, stream := range streams {
			s.pingChan <- stream
		}
		logger.Tracef("done queuing %d pings", len(streams))
	}

	close(s.pingerTerminatedChan)
}

func (s *Service) pingWorker(logger logging.TraceLogger) {
	logger = logging.NewTraceLoggerFromLogger("pingeworker", logger)

	limiter := rate.NewLimiter(rate.Every(pingMaxRate), 1)
	lastSequence := uint64(1)
	for stream := range s.pingChan {
		limiter.Wait(context.Background())

		peerName := "unknown"
		remotePeer, ok := peer.FromContext(stream.Context())
		if ok {
			peerName = remotePeer.Addr.String()
		}
		if err := stream.Send(&protov1.ResponseStream{
			Stream: &protov1.ResponseStream_Ping{
				Ping: &protov1.Ping{
					Sequence:      lastSequence,
					PingTimestamp: timestamppb.Now(),
				},
			},
		}); err != nil {
			logger.Warnf("unable to ping remote: %v", peerName)
		}
	}
}

func newRemoteError(err error) error {
	return &remoteError{
		Err: err,
	}
}

func IsRemoteError(err error) bool {
	_, ok := err.(*remoteError)
	return ok
}

func (e *remoteError) Error() string {
	return fmt.Sprintf("remote error: %v", e.Err)
}

func (r *remoteHost) String() string {
	return fmt.Sprintf("%s.%s<-%v", r.hostname, r.domain, r.peer.Addr)
}
