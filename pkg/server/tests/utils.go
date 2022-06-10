// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/server"
	"github.com/technicianted/whip/pkg/tlsutils"
	"github.com/technicianted/whip/pkg/types"

	"github.com/stretchr/testify/require"
)

var _ types.Dialer = &ServerWrapper{}

type ServerWrapper struct {
	Server  *server.Server
	Options server.ServerOptions

	TLSCertPath string
	TLSKeyPath  string
}

func CreateNewServer(t *testing.T) *ServerWrapper {
	options := server.ServerOptions{
		ExternalTCPHost: "127.0.0.1",
		ExternalTCPPort: 8088,
		TCPListenPort:   8088,
		GRPCListenPort:  8089,
	}
	s := server.NewServer(options)
	return &ServerWrapper{
		Server:  s,
		Options: options,
	}
}

func CreateNewTLSServer(ca *tlsutils.SelfSignedCA, validUntil time.Time, t *testing.T) *ServerWrapper {
	certBytes, keyBytes, err := ca.CreateAndSignCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),
		Subject: pkix.Name{
			Organization:  []string{"TechTed"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Tech"},
			StreetAddress: []string{"Ted"},
			PostalCode:    []string{"11111"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     validUntil,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	})
	require.NoError(t, err)
	certFile, err := ioutil.TempFile("/tmp/", "whiptls")
	require.NoError(t, err)
	defer certFile.Close()
	err = ioutil.WriteFile(certFile.Name(), certBytes, os.ModePerm)
	require.NoError(t, err)
	defer func() {
		if err != nil {
			os.Remove(certFile.Name())
		}
	}()
	keyFile, err := ioutil.TempFile("/tmp/", "wiptls")
	require.NoError(t, err)
	defer keyFile.Close()
	err = ioutil.WriteFile(keyFile.Name(), keyBytes, os.ModePerm)
	require.NoError(t, err)
	defer func() {
		if err != nil {
			os.Remove(keyFile.Name())
		}
	}()
	caCertFile, err := ioutil.TempFile("/tmp/", "whiptls")
	require.NoError(t, err)
	defer caCertFile.Close()
	err = ioutil.WriteFile(caCertFile.Name(), ca.CACertBytes(), os.ModePerm)
	require.NoError(t, err)
	defer func() {
		if err != nil {
			os.Remove(caCertFile.Name())
		}
	}()

	options := server.ServerOptions{
		ExternalTCPHost: "127.0.0.1",
		ExternalTCPPort: 8088,
		TCPListenPort:   8088,
		GRPCListenPort:  8089,
		TLS:             true,
		TLSKeyPath:      keyFile.Name(),
		TLSCertPath:     certFile.Name(),
		TLSCACertPath:   caCertFile.Name(),
	}
	s := server.NewServer(options)
	return &ServerWrapper{
		Server:  s,
		Options: options,
	}
}

func (s *ServerWrapper) Start(t *testing.T, logger logging.TraceLogger) {
	require.NoError(t, s.Server.Start(logger))
}

func (s *ServerWrapper) Stop(t *testing.T, logger logging.TraceLogger) {
	os.Remove(s.Options.TLSCACertPath)
	os.Remove(s.Options.TLSKeyPath)
	require.NoError(t, s.Server.Stop(logger))
}

func (s *ServerWrapper) DialContext(ctx context.Context, network, address string, logger logging.TraceLogger, opts ...types.DialOption) (net.Conn, error) {
	return s.Server.DialContext(ctx, network, address, logger, opts...)
}
