// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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
	proxyTLS                  bool
	proxyTLSKeyPath           string
	proxyTLSCertPath          string
	basicAuthUsername         string
	basicAuthPasswordEnvName  string
	basicAuthPasswordPath     string
	target                    string
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
	proxyCMD.Flags().BoolVar(&proxyTLS, "proxy-tls", false, "enable tls for proxy listener")
	proxyCMD.Flags().StringVar(&proxyTLSKeyPath, "proxy-tls-key-path", "", "path to tls private key in pem format for proxy tls")
	proxyCMD.Flags().StringVar(&proxyTLSCertPath, "proxy-tls-cert-path", "", "path to tls certificate in pem format for proxy tls")
	proxyCMD.Flags().StringVar(&basicAuthUsername, "proxy-auth-username", "whipproxy", "username to use for proxy basic auth")
	proxyCMD.Flags().StringVar(&basicAuthPasswordEnvName, "proxy-auth-password-env", "WHIP_PROXY_PASSWORD", "environment variable with proxy basic auth password")
	proxyCMD.Flags().StringVar(&basicAuthPasswordPath, "proxy-auth-password-path", "", "path to proxy requests auth key")
	proxyCMD.Flags().StringVar(&target, "target", "", "specifies a single-host target for the proxy where all requests will go to target")
	cmd.RootCMD.AddCommand(proxyCMD)
}

func proxyFunc(command *cobra.Command, args []string) {
	logger := logging.NewTraceLogger("controller")
	logger.Warnf("THIS PROXY IS FOR EXPERIMENTATION ONLY!")

	cmd.CommonSetup(logger)

	logger.Infof("whip version %v", version.Build)

	singleHost := len(target) > 0

	serverOptions := server.ServerOptions{
		ExternalTCPHost: externalTCPHost,
		ExternalTCPPort: externalTCPPort,
		TCPListenPort:   tcpListenPort,
		GRPCListenPort:  grpcListenPort,
		TLS:             cmd.TLS,
		TLSKeyPath:      cmd.TLSKeyPath,
		TLSCertPath:     cmd.TLSCertPath,
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

	proxyListenAddress := ""
	basicAuthPassword := ""
	if envPassword, ok := os.LookupEnv(basicAuthPasswordEnvName); ok {
		logger.Infof("using environemnt variable %s for basic auth password", basicAuthPasswordEnvName)
		basicAuthPassword = envPassword
	} else if basicAuthPasswordPath != "" {
		if bytes, err := ioutil.ReadFile(basicAuthPasswordPath); err != nil {
			logger.Fatalf("failed to read password from file %s: %v", basicAuthPasswordPath, err)
		} else {
			logger.Infof("using file %s for bsic auth password", basicAuthPasswordPath)
			basicAuthPassword = string(bytes)
		}
	}
	if basicAuthPassword == "" || basicAuthUsername == "" {
		logger.Infof("proxy basic auth is disabled, using 127.0.0.1 as listen address")
		basicAuthPassword = ""
		basicAuthUsername = ""
		proxyListenAddress = "127.0.0.1"
	}

	proxyListenAddress = fmt.Sprintf("%s:%d", proxyListenAddress, proxyListenPort)
	logger.Infof("proxy listening on %s", proxyListenAddress)
	httpLis, err := net.Listen("tcp", proxyListenAddress)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}

	var httpProxy http.Handler
	if singleHost {
		targetURL, err := url.Parse(target)
		if err != nil {
			logger.Fatalf("failed to parse target %s: %v", target, err)
		}
		logger.Infof("using single host proxy to: %s", target)
		httpProxy = proxy.NewSingleHost(dialer, downstreamRequestIDheader, basicAuthUsername, basicAuthPassword, targetURL)
	} else {
		httpProxy = proxy.NewHTTP(dialer, downstreamRequestIDheader, basicAuthUsername, basicAuthPassword)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	httpServer := &http.Server{
		Handler: httpProxy,
	}
	go func() {
		if proxyTLS {
			logger.Infof("running https proxy")
			if err := httpServer.ServeTLS(httpLis, proxyTLSCertPath, proxyTLSKeyPath); err != http.ErrServerClosed {
				logger.Fatalf("failed to serve https: %v", err)
			}
		} else {
			logger.Infof("running http proxy")
			if err := httpServer.Serve(httpLis); err != http.ErrServerClosed {
				logger.Fatalf("failed to serve http: %v", err)
			}
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
