// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package createandsign

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/technicianted/whip/cmd/whiphack/cmd"
	"github.com/technicianted/whip/cmd/whiphack/cmd/pki"
	"github.com/technicianted/whip/pkg/logging"

	"github.com/spf13/cobra"
)

var ServerCMD = &cobra.Command{
	Use:   "server",
	Short: "creates a new key pair and signs them with a ca suitable for tls server",
	Run:   runServer,
}

var (
	dnsNames []string
)

func init() {
	ServerCMD.Flags().StringSliceVar(&dnsNames, "dns-names", nil, "dns names to be used for verification")

	CreateAndSignCMD.AddCommand(ServerCMD)
}

func runServer(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("createandsignserver")
	cmd.SetLogging(logger)

	logger.Warnf("this is a hacking tool and is only suitable for quick testing!")

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),
		Subject:      pki.Subject,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(pki.ValidityDuration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: dnsNames,
	}

	createAndSign(cert, logger)

	logger.Infof("done")
}
