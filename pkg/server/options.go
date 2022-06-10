// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package server

// ServerOptions is a set of whip service options.
type ServerOptions struct {
	// ExternalTCPHost is the fqdn or ip address of this whip service instance
	// that can be externally reached by remote clients for tcp connections.
	ExternalTCPHost string
	// External TCPPort is the port number available externally to clients to connect
	// remote tcp connections.
	ExternalTCPPort int
	// TCPListenPort is the port to listen on for incoming remote tcp connections.
	TCPListenPort int
	// GRPCListenPort is the port to listen on for incoming grpc control connections.
	GRPCListenPort int
	// TLS enables or disables tls for both grpc and reverse tcp connections.
	TLS bool
	// TLSKeyPath is the path to the tls pem key for the service.
	TLSKeyPath string
	// TLSCertPath is the path to the tls pem certificate for the service.
	TLSCertPath string
	// TLSCACertPath is the path to the tls pem ca certificate to be used to verify remote clients.
	TLSCACertPath string
}
