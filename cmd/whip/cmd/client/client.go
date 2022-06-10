// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/technicianted/whip/cmd/whip/cmd"
	whipclient "github.com/technicianted/whip/pkg/client"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/version"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var clientCMD = &cobra.Command{
	Use:   "client",
	Short: "start whip client",
	Long:  "start whip client that establishes reverse tcp tunnels",
	Run:   clientFunc,
}

var (
	hostname string
	domain   string
	ports    []int

	GRPCDialOptions []grpc.DialOption
)

func init() {
	if h, err := os.Hostname(); err == nil {
		hostname = h
	}
	clientCMD.Flags().StringVar(&hostname, "hostname", hostname, "hostname to use for registration")
	clientCMD.Flags().StringVar(&domain, "domain", "", "domain name to use for registration")
	clientCMD.MarkFlagRequired("domain")
	clientCMD.Flags().IntSliceVar(&ports, "ports", nil, "list of local port numbers to expose")
	clientCMD.MarkFlagRequired("ports")
	clientCMD.Use = "client [flags] <service_endpoint> [<service_endpoint>] ..."

	cmd.RootCMD.AddCommand(clientCMD)
}

func clientFunc(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("controller")
	cmd.CommonSetup(logger)

	logger.Infof("whip version %v", version.Build)

	whipServiceEndpoints := args
	if len(whipServiceEndpoints) == 0 {
		logger.Fatalf("no whip service endpoint specified")
	}

	clientOptions := whipclient.ClientOptions{
		WhipServiceEndpoints: whipServiceEndpoints,
		Hostname:             hostname,
		Domain:               domain,
		Ports:                ports,
		TLS:                  cmd.TLS,
		TLSKeyPath:           cmd.TLSKeyPath,
		TLSCertPath:          cmd.TLSCACertPath,
		TLSCACertPath:        cmd.TLSCACertPath,
	}

	logger.Tracef("starting client options: %+v", clientOptions)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	client := whipclient.NewClient(clientOptions)
	if err := client.Start(logger); err != nil {
		logger.Fatalf("failed to start client: %v", err)
	}

	logger.Infof("startup sequence completed")
	<-sigChan
	logger.Infof("received shutdown signal")
	if err := client.Stop(logger); err != nil {
		logger.Warnf("failed to stop client: %v", err)
	}

	logger.Infof("shutdown completed")
}
