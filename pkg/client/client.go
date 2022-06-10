// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/technicianted/whip/pkg/client/types"
	"github.com/technicianted/whip/pkg/logging"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// DefaultReconciliationDuration is the default endpoint/client reconciliation interval.
	DefaultReconciliationDuration = 5 * time.Second
)

// clientEntry used to represent a single whip client connected to a single whip service
// instance.
type clientEntry struct {
	// client is the whip client instance.
	client types.ClientManager
	// reconcilerKey is the key assigned to this instance by types.ClientReconciler.
	reconcilerKey string
}

var _ types.ClientFactory = &Client{}
var _ types.WhipEndpointResolver = &Client{}

// Client is a higher level whip client that wraps one or more whip clients, each
// connected to a single physical whip service instance.
// It continuously reconciles current connected clients with given endpoints and their
// resolved ip addresses and performs necessary operations to create or remove.
type Client struct {
	options                      ClientOptions
	clientFactory                types.ClientFactory
	clientReconciler             types.ClientReconciler
	clientReconciliationDuration time.Duration
	whipClients                  map[string]clientEntry
	stopChan                     chan interface{}
	reconcilerStoppedChan        chan interface{}
}

// NewClient creates a new client with options. Internally, it creates one or more
// clients each connected to a physical whip service instance.
func NewClient(options ClientOptions) *Client {
	c := &Client{
		options:                      options,
		whipClients:                  make(map[string]clientEntry),
		clientReconciliationDuration: DefaultReconciliationDuration,
	}
	c.clientFactory = c
	c.clientReconciler = newReconciler(c)
	return c
}

// Start starts the client instance and its reconciliation loop. It continuously
// monitors endpoints and creates or removes clients accordingly.
// The function will block until the first reconciliation loop finishes.
func (c *Client) Start(logger logging.TraceLogger) error {
	logger.Infof("starting client with options: %+v", c.options)

	c.doSingleUpdate(logger)

	c.stopChan = make(chan interface{})
	c.reconcilerStoppedChan = make(chan interface{})
	go c.clientsUpdateLoop(logger)

	return nil
}

// Stop stops the client instance and all of its connected clients causing them
// to disconnect for whip service.
// The function will block until all clients are disconnected.
func (c *Client) Stop(logger logging.TraceLogger) error {
	logger.Infof("stopping client")

	close(c.stopChan)
	logger.Infof("waiting for reconciliation to stop")
	<-c.reconcilerStoppedChan

	logger.Infof("stopping %d clients", len(c.whipClients))
	for _, client := range c.whipClients {
		if err := client.client.Stop(logger); err != nil {
			logger.Warnf("failed to stop client %s: %v", client.reconcilerKey, err)
		}
	}

	return nil
}

// NewClient implement types.ClientFactory
func (c *Client) NewClient(options types.NewClientOptions, logger logging.TraceLogger) (types.ClientManager, error) {
	whipClient := NewWhipClient(options.ClientConn, options.ConnDialer, options.Hostname, options.Domain, options.ExposedPorts)
	return whipClient, nil
}

// Resolve implements types.WhipEndpointResolver
func (c *Client) Resolve(ctx context.Context, hostname string) (addresses []string, err error) {
	// little hack for endpoints in the form of ":8080"
	if hostname == "" {
		return []string{"0.0.0.0"}, nil
	}
	return (&net.Resolver{}).LookupHost(ctx, hostname)
}

func (c *Client) clientsUpdateLoop(logger logging.TraceLogger) {
	logger.Infof("starting clients update loop with %d grpc endpoints", len(c.options.WhipServiceEndpoints))
	done := false
	for !done {
		select {
		case <-time.After(c.clientReconciliationDuration):
		case <-c.stopChan:
			done = true
		}
		c.doSingleUpdate(logger)
	}
	logger.Infof("reconcilation loop stopped")
	close(c.reconcilerStoppedChan)
}

func (c *Client) doSingleUpdate(logger logging.TraceLogger) {
	keys := []string{}
	for key := range c.whipClients {
		keys = append(keys, key)
	}

	removedKeys, addedClients, err := c.clientReconciler.Reconcile(context.TODO(), c.options.WhipServiceEndpoints, keys, logger)
	if err != nil {
		logger.Errorf("failed to reconcile clients: %v", err)
	} else {
		if len(removedKeys) > 0 {
			logger.Infof("removing %d clients", len(removedKeys))
		}
		for _, key := range removedKeys {
			logger.Infof("stopping client %s", key)
			if entry, ok := c.whipClients[key]; ok {
				if err := entry.client.Stop(logger); err != nil {
					logger.Errorf("failed to stop client: %v", err)
				}
				delete(c.whipClients, key)
			} else {
				logger.Warnf("client with key %s not found", key)
			}
		}

		if len(addedClients) > 0 {
			logger.Infof("adding %d clients", len(addedClients))
		}
		for _, client := range addedClients {
			logger.Infof("adding new client %s", client.Key)
			opts, err := c.getNewClientOptions(client, logger)
			if err != nil {
				logger.Errorf("failed to get client options: %v", err)
				continue
			}
			whipClient, err := c.clientFactory.NewClient(opts, logger)
			if err != nil {
				logger.Errorf("failed to create client: %v", err)
				continue
			}
			if err := whipClient.Start(logger); err != nil {
				logger.Errorf("failed to start client: %v", err)
				continue
			}
			c.whipClients[client.Key] = clientEntry{
				client:        whipClient,
				reconcilerKey: client.Key,
			}
		}
	}
}

func (c *Client) getNewClientOptions(client types.ReconcilerClientInfo, logger logging.TraceLogger) (opts types.NewClientOptions, err error) {
	conn, err := c.setupGRPCConn(client.Endpoint, client.Authority, logger)
	if err != nil {
		return
	}

	dialer, err := c.setupTCPDialer(logger)
	if err != nil {
		return
	}

	opts.ClientConn = conn
	opts.ConnDialer = dialer
	opts.Hostname = c.options.Hostname
	opts.Domain = c.options.Domain
	opts.ExposedPorts = c.options.Ports

	return
}

func (c *Client) setupGRPCConn(endpoint, authority string, logger logging.TraceLogger) (*grpc.ClientConn, error) {
	dialOptions := c.options.GRPCDialOptions
	credOptions, err := c.getGRPCCredentialOptions(logger)
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, credOptions...)
	if authority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(authority))
	}

	conn, err := grpc.Dial(endpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %v", endpoint, err)
	}

	return conn, nil
}

func (c *Client) getGRPCCredentialOptions(logger logging.TraceLogger) ([]grpc.DialOption, error) {
	if !c.options.TLS {
		logger.Infof("using plain text grpc")
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}

	tlsConfig, err := c.getTLSConfig(logger)
	if err != nil {
		return nil, err
	}

	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

func (c *Client) getTLSConfig(logger logging.TraceLogger) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.options.TLSCertPath, c.options.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate at %s, %s: %v", c.options.TLSCertPath, c.options.TLSKeyPath, err)
	}

	var caCertPool *x509.CertPool
	if c.options.TLSCACertPath != "" {
		caCertPool = x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(c.options.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca certificate file: %v", err)
		}
		if !caCertPool.AppendCertsFromPEM(caCertBytes) {
			return nil, fmt.Errorf("failed to load ca certificate: %v", err)
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
}

func (c *Client) setupTCPDialer(logger logging.TraceLogger) (types.ClientConnDialer, error) {
	if !c.options.TLS {
		logger.Infof("using plain text tcp dialer")
		return &tcpPlainTextDialer{}, nil
	}

	tlsConfig, err := c.getTLSConfig(logger)
	if err != nil {
		return nil, err
	}

	return &tcpTLSDialer{
		config: tlsConfig,
	}, nil
}

type tcpPlainTextDialer struct{}

func (d *tcpPlainTextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

type tcpTLSDialer struct {
	config *tls.Config
}

func (d *tcpTLSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    d.config,
	}).DialContext(ctx, network, address)
}
