// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import "google.golang.org/grpc"

// ClientOptions is a set of options used when creating new
// clients.
type ClientOptions struct {
	// WhipServiceEndpoints is an array of whip service grpc endpoints. Each one
	// will be resolved into 1 or more ip addresses and a whip client will be created
	// for each one of them.
	WhipServiceEndpoints []string
	// Hostname is the client hostname. It will be used in registration with whip service.
	// It does not need to match the actual hostname.
	Hostname string
	// Domain is the client domain name. It will be used in registration with whip service.
	// It does not need to match the actual hostname. In fact it is recommended not to use
	// common, publicly accessible domains.
	Domain string
	// Ports is a list of published tcp ports that this client is willing to accept connections
	// to.
	Ports []int
	// GRPCDialOptions is a list of grpc dial options to be used when dialing to whip service
	// grpc.
	GRPCDialOptions []grpc.DialOption
	// TLS enables the use of tls for both grpc control connection to whip server, and reverse
	// tunneled tcp connections.
	TLS bool
	// TLSKeyPath is the path to the tls client key.
	TLSKeyPath string
	// TLSCertPAth is the path to the client tls certificate.
	TLSCertPath string
	// TLSCACertPath is the path to the ca certificate. It will be used to verify whip service
	// certificates.
	TLSCACertPath string
}
