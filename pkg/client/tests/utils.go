// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/technicianted/whip/pkg/tlsutils"
)

func NewTLSClientCert(ca *tlsutils.SelfSignedCA, cert *x509.Certificate, t *testing.T) (caCertPath, certPath, keyPath string) {
	certBytes, keyBytes, err := ca.CreateAndSignCertificate(cert)
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

	return caCertFile.Name(), certFile.Name(), keyFile.Name()
}
