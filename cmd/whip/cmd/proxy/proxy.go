// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/technicianted/whip/cmd/whip/cmd"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/proxy"
	"github.com/technicianted/whip/pkg/server"
	"github.com/technicianted/whip/pkg/types"
	"github.com/technicianted/whip/version"

	"github.com/spf13/cobra"
)

var proxyCMD = &cobra.Command{
	Use:   "proxy",
	Short: "start whip http service proxy",
	Run:   proxyFunc,
}

var (
	externalTCPHost           string
	externalTCPPort           int
	tcpListenPort             int
	grpcListenPort            int
	proxyListenPort           int
	downstreamRequestIDheader string
	fallbackProxy             bool
)

func init() {
	proxyCMD.Flags().StringVar(&externalTCPHost, "whip-external-tcp-address", "", "address or fqdn hostname that remote clients can connect to for tcp")
	proxyCMD.MarkFlagRequired("whip-external-tcp-address")
	proxyCMD.Flags().IntVar(&externalTCPPort, "whip-external-tcp-port", 0, "external port that remote clients can connect to for tcp")
	proxyCMD.MarkFlagRequired("whip-external-tcp-port")
	proxyCMD.Flags().IntVar(&tcpListenPort, "whip-tcp-listen-port", 8000, "local port to listen on for remote tcp connections that external-tcp-address:external-tcp-port maps to")
	proxyCMD.Flags().IntVar(&grpcListenPort, "whip-grpc-listen-port", 8001, "local port to listen on for remote grpc whip control requests")
	proxyCMD.Flags().IntVar(&proxyListenPort, "proxy-listen-port", 8008, "proxy listen port")
	proxyCMD.Flags().StringVar(&downstreamRequestIDheader, "downstream-request-id-header", "", "header name that contains the request ID from downstream")
	proxyCMD.Flags().BoolVar(&fallbackProxy, "fallback", false, "fallback to standard forwarding if upstream host is not whip")

	cmd.RootCMD.AddCommand(proxyCMD)
}

func proxyFunc(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("controller")
	logger.Warnf("THIS PROXY IS FOR EXPERIMENTATION ONLY!")

	cmd.CommonSetup(logger)

	logger.Infof("whip version %v", version.Build)

	serverOptions := server.ServerOptions{
		ExternalTCPHost: externalTCPHost,
		ExternalTCPPort: externalTCPPort,
		TCPListenPort:   tcpListenPort,
		GRPCListenPort:  grpcListenPort,
		TLS:             cmd.TLS,
		TLSKeyPath:      cmd.TLSKeyPath,
		TLSCertPath:     cmd.TLSCACertPath,
		TLSCACertPath:   cmd.TLSCACertPath,
	}

	whipServer := server.NewServer(serverOptions)
	if err := whipServer.Start(logger); err != nil {
		logger.Fatalf("failed to start whip server: %v", err)
	}

	var dialer types.Dialer
	if fallbackProxy {
		logger.Infof("using fallback proxy")
		dialer = proxy.NewFallbackDialer(whipServer, server.WithWaitForHost(false))
	} else {
		dialer = whipServer
	}

	proxyListenAddress := fmt.Sprintf("127.0.0.1:%d", proxyListenPort)
	logger.Infof("proxy listening on %s", proxyListenAddress)
	httpLis, err := net.Listen("tcp", proxyListenAddress)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}

	httpProxy := proxy.NewHTTP(dialer, downstreamRequestIDheader)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	httpServer := &http.Server{
		Handler: httpProxy,
	}
	go func() {
		if err := httpServer.Serve(httpLis); err != http.ErrServerClosed {
			logger.Errorf("failed to serve http: %v", err)
		}
	}()

	logger.Infof("startup sequence completed")
	<-sigChan
	logger.Infof("received shutdown signal")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Warnf("failed to shutdown server: %v", err)
	}

	if err := whipServer.Stop(logger); err != nil {
		logger.Warnf("failed to stop whip server: %v", err)
	}

	logger.Infof("shutdown completed")
}
