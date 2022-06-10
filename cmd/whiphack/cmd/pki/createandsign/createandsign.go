// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package createandsign

import (
	"crypto/x509"
	"io/ioutil"
	"net"
	"os"

	"github.com/technicianted/whip/cmd/whiphack/cmd/pki"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/tlsutils"

	"github.com/spf13/cobra"
)

var CreateAndSignCMD = &cobra.Command{
	Use:   "createandsign",
	Short: "creates and sign new key pair and signs them with a ca",
}

var (
	certPath    string
	keyPath     string
	ipAddresses []net.IP
)

func init() {
	CreateAndSignCMD.PersistentFlags().StringVar(&certPath, "cert-path", "cert.pem", "path to certificate pem file")
	CreateAndSignCMD.PersistentFlags().StringVar(&keyPath, "key-path", "key.pem", "path to key pem file")
	CreateAndSignCMD.PersistentFlags().IPSliceVar(&ipAddresses, "ip-address", nil, "allowed ip addresses")

	pki.PKICMD.AddCommand(CreateAndSignCMD)
}

func createAndSign(cert *x509.Certificate, logger logging.TraceLogger) {
	logger.Infof("loading ca")
	ca, err := tlsutils.NewCAFromFiles(pki.CAKeyPath, pki.CACertPath)
	if err != nil {
		logger.Fatalf("failed to load ca: %v", err)
	}

	logger.Infof("creating and signing new key pair with subject: %+v", pki.Subject)

	certBytes, keyBytes, err := ca.CreateAndSignCertificate(cert)
	if err != nil {
		logger.Fatalf("failed to create certificate: %v", err)
	}
	if err := ioutil.WriteFile(keyPath, keyBytes, 0600); err != nil {
		logger.Fatalf("failed to write key: %v", err)
	}
	if err := ioutil.WriteFile(certPath, certBytes, os.ModePerm); err != nil {
		logger.Fatalf("failed to write cert: %v", err)
	}
}
