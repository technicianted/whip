// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/technicianted/whip/pkg/client"
	clienttest "github.com/technicianted/whip/pkg/client/tests"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/server"
	"github.com/technicianted/whip/pkg/tlsutils"

	"github.com/stretchr/testify/require"
)

const (
	testDomain = "testdomain"
)

func TestServiceTLSSimple(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	testString := "hello, world!"
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testString)
	}))
	u, err := url.Parse(httpServer.URL)
	require.NoError(t, err)
	localPort, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	ca, err := tlsutils.NewSelfSignedCA(pkix.Name{
		Organization:  []string{"TechTed"},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"Tech"},
		StreetAddress: []string{"Ted"},
		PostalCode:    []string{"11111"},
	}, time.Now().Add(1*time.Minute))
	require.NoError(t, err)
	s := CreateNewTLSServer(ca, time.Now().Add(1*time.Minute), t)
	s.Start(t, logger)
	defer s.Stop(t, logger)

	caPath, certPath, keyPath := clienttest.NewTLSClientCert(
		ca,
		&x509.Certificate{
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
			DNSNames:     []string{"*." + testDomain},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(1 * time.Minute),
			SubjectKeyId: []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		},
		t)
	defer os.Remove(caPath)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	client := client.NewClient(client.ClientOptions{
		WhipServiceEndpoints: []string{fmt.Sprintf("127.0.0.1:%d", s.Options.GRPCListenPort)},
		Hostname:             "testhost",
		Domain:               testDomain,
		Ports:                []int{localPort},
		TLS:                  true,
		TLSKeyPath:           keyPath,
		TLSCertPath:          certPath,
		TLSCACertPath:        caPath,
	})
	err = client.Start(logger)
	require.NoError(t, err)
	defer client.Stop(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	conn, err := s.DialContext(ctx, "tcp", fmt.Sprintf("testhost.%s:%d", testDomain, localPort), logger, server.WithWaitForHost(true))
	require.NoError(t, err)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://testhost.testdomain:%d", localPort), nil)
	require.NoError(t, err)
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, testString, string(body))
}
