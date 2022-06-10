// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package types

import (
	"context"
	"net"

	"github.com/technicianted/whip/pkg/logging"
	"google.golang.org/grpc"
)

// ClientConnDialer is an interface used by the client to dial outgoing tcp connections.
// It abstracts away plaintext vs tls tcp connections.
type ClientConnDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewClientOptions used to configure a new whip client
type NewClientOptions struct {
	// ClientConn is the grpc connection to be used to talk to whip grpc control service.
	ClientConn *grpc.ClientConn
	// ConnDialer is an interface to use to dial outgoing tcp connection when requested by whip control service.
	ConnDialer ClientConnDialer
	// Hostname is the hostname to be used when registering with whip service. It will be used
	// to identify this particular client to remote clients.
	Hostname string
	// Domain is the domain to be used when registering with whip service. It will be used
	// to identify this client as Hostname.Domain.
	Domain string
	// ExposedPorts is an array of local tcp ports to advertise to whip service for remote clients
	// to connect to.
	ExposedPorts []int
}

// ClientFactory defines a factory interface to create new client instances.
type ClientFactory interface {
	NewClient(options NewClientOptions, logger logging.TraceLogger) (ClientManager, error)
}

// ClientManager defines an interface for managed clients.
type ClientManager interface {
	Start(logger logging.TraceLogger) error
	Stop(logger logging.TraceLogger) error
}

// WhipEndpointResolver defines an interface to abstract grpc endpoint resolution to ip addresses.
// Used by whip client to resolve given endpoints and establishing grpc connection to all whip
// service instances.
type WhipEndpointResolver interface {
	// Resolve resolves a given hostname into a set of ip addresses.
	Resolve(ctx context.Context, hostname string) (addresses []string, err error)
}

// ReconcilerClientInfo is a struct representing a single whip client connected to a single
// whip service instance.
type ReconcilerClientInfo struct {
	// Key is a unique key identifying this instance.
	Key string
	// Endpoint is the canoncialized endpoint that this client is connected to.
	Endpoint string
	// Hostname is the hostname segment of Endpoint.
	Hostname string
	// Port is the endpoint port segment.
	Port string
	// Authority is the http2 authority to use when making the grpc call. It is
	// used as the endpoint hostname can resolve to multiple ip addresses which
	// will be used to establish connection to each one of them.
	Authority string
	// IPAddress is the whip service ip address that this client instance is connected to.
	IPAddress string
}

// ClientReconciler is an interface representing a reconciler that can continuously manage
// a set of clients and advises on which clients need termination and which ones should be
// created.
type ClientReconciler interface {
	// Reconcile performs a pass on currentClientKeys of existing clients on endpoints. It returns
	// a list of clients that should be removed or added based on changes in endpoints.
	Reconcile(ctx context.Context, endpoints []string, currentClientKeys []string, logger logging.TraceLogger) (removedClients []string, addedClients []ReconcilerClientInfo, err error)
}
