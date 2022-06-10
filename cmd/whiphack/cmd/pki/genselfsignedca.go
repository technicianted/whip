// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package pki

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/technicianted/whip/cmd/whiphack/cmd"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/tlsutils"

	"github.com/spf13/cobra"
)

var GenSelfsignedCACMD = &cobra.Command{
	Use:   "genselfsignedca",
	Short: "generate a self-signed CA",
	Run:   runGenSelfSignedCA,
}

func init() {
	PKICMD.AddCommand(GenSelfsignedCACMD)
}

func runGenSelfSignedCA(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("genselfsigned")
	cmd.SetLogging(logger)

	logger.Warnf("this is a hacking tool and is only suitable for quick testing!")

	logger.Infof("generating a new self-signed CA with subject: %+v", Subject)
	ca, err := tlsutils.NewSelfSignedCA(Subject, time.Now().Add(ValidityDuration))
	if err != nil {
		logger.Fatalf("failed to create ca: %v", err)
	}

	if err := ioutil.WriteFile(CACertPath, ca.CACertBytes(), os.ModePerm); err != nil {
		logger.Fatalf("failed to write certificate: %v", err)
	}
	if err := ioutil.WriteFile(CAKeyPath, ca.CAKeyBytes(), 0600); err != nil {
		logger.Fatalf("failed to write key: %v", err)
	}

	logger.Infof("done")
}
