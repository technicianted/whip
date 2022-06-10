// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package cmd

import (
	"net/http"

	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/metrics"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// RootCMD is the base command
var RootCMD = &cobra.Command{
	Use:   "whip",
	Short: "whip reverse tcp proxy",
}

var (
	LogLevel             string
	MetricsListenAddress string
	PProfListenAddress   string

	TLS           bool
	TLSKeyPath    string
	TLSCertPath   string
	TLSCACertPath string
)

func init() {
	RootCMD.PersistentFlags().StringVar(&MetricsListenAddress, "metrics-listen", ":8080", "prometheus metric exposer listen address")
	RootCMD.PersistentFlags().StringVar(&LogLevel, "log-level", "info", "set log level")
	RootCMD.PersistentFlags().StringVar(&PProfListenAddress, "pprof-listen", ":6060", "go pprof http listen address")

	RootCMD.PersistentFlags().BoolVar(&TLS, "tls", true, "enable mutual tls authentication")
	RootCMD.PersistentFlags().StringVar(&TLSKeyPath, "tls-key-path", "", "path to tls private key in pem format")
	RootCMD.MarkFlagFilename("tls-key-path")
	RootCMD.PersistentFlags().StringVar(&TLSCertPath, "tls-cert-path", "", "path to tls certificate in pem format")
	RootCMD.MarkFlagFilename("tls-cert-path")
	RootCMD.PersistentFlags().StringVar(&TLSCACertPath, "tls-ca-cert-path", "", "path to ca certificate pem format used to authenticate peer")
	RootCMD.MarkFlagFilename("tls-ca-cert-path")
}

func CommonSetup(logger logging.TraceLogger) {
	setLogging(logger, LogLevel)
	setupPProf(logger, PProfListenAddress)
	setupMetrics(logger, MetricsListenAddress)
}

func setLogging(logger logging.TraceLogger, logLevel string) {
	log.SetFormatter(&logging.LogFormatter{})

	switch logLevel {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	default:
		logger.Fatalf("invalid log level: %s", logLevel)
	}

	healthLogger := log.New()
	healthLogger.SetFormatter(&logging.LogFormatter{})
	healthLogger.SetLevel(log.ErrorLevel)

	logger.Infof("setting log level to %s", logLevel)
}

func setupPProf(logger logging.TraceLogger, pprofListenAddress string) {
	if pprofListenAddress != "" {
		go func() {
			logger.Infof("starting pprof http handler on: %v", pprofListenAddress)
			err := http.ListenAndServe(pprofListenAddress, nil)
			logger.Infof("pprof http handler terminated: %v", err)
		}()
	}
}

func setupMetrics(logger logging.TraceLogger, metricsListenAddress string) {
	if metricsListenAddress != "" {
		metrics.StartMetricsExposer(metricsListenAddress, logger)
	}
}
