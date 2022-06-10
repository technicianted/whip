// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package createandsign

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/spf13/cobra"
	"github.com/technicianted/whip/cmd/whiphack/cmd"
	"github.com/technicianted/whip/cmd/whiphack/cmd/pki"
	"github.com/technicianted/whip/pkg/logging"
)

var ClientCMD = &cobra.Command{
	Use:   "client",
	Short: "creates a new key pair and signs them with a ca suitable for tls clients",
	Run:   runClient,
}

var (
	hostname string
	domain   string
)

func init() {
	ClientCMD.Flags().StringVar(&hostname, "hostname", "*", "hostname to be used for certificate for client identity, must match client registration hostname")
	ClientCMD.Flags().StringVar(&domain, "domain", "", "domain to be used for certificate for client identity, must match client registration domain")
	ClientCMD.MarkFlagRequired("domain")

	CreateAndSignCMD.AddCommand(ClientCMD)
}

func runClient(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("createandsignclient")
	cmd.SetLogging(logger)

	logger.Warnf("this is a hacking tool and is only suitable for quick testing!")

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),
		Subject:      pki.Subject,
		IPAddresses:  ipAddresses,
		DNSNames:     []string{hostname + "." + domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(pki.ValidityDuration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	createAndSign(cert, logger)

	logger.Infof("done")
}
