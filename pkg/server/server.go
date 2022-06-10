// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/technicianted/whip/pkg/logging"
	protov1 "github.com/technicianted/whip/pkg/proto/v1"
	"github.com/technicianted/whip/pkg/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var _ types.Dialer = &Server{}

// Server implements a convenient wrapper around Service to provide functionalities
// such as tls certificate loading, tcp dialer and listener creation and its tls wrappers.
// Server implements types.Dialer so it can be used as a drop-in for Service.
type Server struct {
	options      ServerOptions
	service      *Service
	tcpListener  net.Listener
	grpcListener net.Listener
	grpcServer   *grpc.Server
}

// NewServer creates a new Server wrapper with options.
func NewServer(options ServerOptions) *Server {
	return &Server{
		options: options,
	}
}

// Start starts the wrapper and its underlying Service. It sets up the tcp listener
// for client connections with tls wrappers, and sets up the grpc service and enables
// tls.
func (s *Server) Start(logger logging.TraceLogger) error {
	logger.Infof("starting server")

	if err := s.setupTCPListener(logger); err != nil {
		return err
	}

	service, err := NewService(
		s.options.ExternalTCPHost,
		s.options.ExternalTCPPort,
		s.tcpListener,
		logger)
	if err != nil {
		return err
	}
	if err := service.Start(logger); err != nil {
		return fmt.Errorf("failed to start whip service: %v", err)
	}
	s.service = service

	s.setupGRPCServer(logger)

	return nil
}

// Stop stops the service wrapper.
func (s *Server) Stop(logger logging.TraceLogger) error {
	logger.Infof("stopping server")

	if s.grpcServer != nil {
		logger.Infof("stopping grpc server")
		s.grpcServer.Stop()
	}
	if s.grpcListener != nil {
		s.grpcListener.Close()
	}
	if s.tcpListener != nil {
		s.grpcListener.Close()
	}

	if err := s.service.Stop(logger); err != nil {
		logger.Warnf("failed to stop whip service: %v", err)
	}

	return nil
}

// DialContext passes the call to the underlying Service DialContext.
func (s *Server) DialContext(ctx context.Context, network, address string, logger logging.TraceLogger, opts ...types.DialOption) (net.Conn, error) {
	return s.service.DialContext(ctx, network, address, logger, opts...)
}

func (s *Server) setupTCPListener(logger logging.TraceLogger) error {
	tcpAddress := fmt.Sprintf("0.0.0.0:%d", s.options.TCPListenPort)
	if !s.options.TLS {
		logger.Infof("using plain text tcp listener")

		lis, err := net.Listen("tcp", tcpAddress)
		if err != nil {
			return err
		}
		s.tcpListener = lis
		return nil
	}

	logger.Infof("using tls tcp listener")
	tlsConfig, err := s.getTLSConfig(logger)
	if err != nil {
		return err
	}
	lis, err := tls.Listen("tcp", tcpAddress, tlsConfig)
	if err != nil {
		return err
	}
	s.tcpListener = lis

	return nil
}

func (s *Server) setupGRPCServer(logger logging.TraceLogger) error {
	credOptions, err := s.getGRPCCredentialOptions(logger)
	if err != nil {
		return err
	}

	address := fmt.Sprintf("0.0.0.0:%d", s.options.GRPCListenPort)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.grpcListener = lis
	s.grpcServer = grpc.NewServer(credOptions...)
	protov1.RegisterWhipServer(s.grpcServer, s.service)

	go func() {
		if err := s.grpcServer.Serve(s.grpcListener); err != nil && err != grpc.ErrServerStopped {
			logger.Errorf("failed to serve grpc: %v", err)
		}
	}()

	return nil
}

func (s *Server) getGRPCCredentialOptions(logger logging.TraceLogger) ([]grpc.ServerOption, error) {
	if !s.options.TLS {
		logger.Infof("not using TLS")
		return []grpc.ServerOption{}, nil
	}

	tlsConfig, err := s.getTLSConfig(logger)
	if err != nil {
		return nil, err
	}

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

func (s *Server) getTLSConfig(logger logging.TraceLogger) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.options.TLSCertPath, s.options.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate at %s, %s: %v", s.options.TLSCertPath, s.options.TLSKeyPath, err)
	}

	var caCertPool *x509.CertPool
	if s.options.TLSCACertPath != "" {
		caCertPool = x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(s.options.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca certificate file: %v", err)
		}
		if !caCertPool.AppendCertsFromPEM(caCertBytes) {
			return nil, fmt.Errorf("failed to load ca certificate: %v", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}, nil
}
