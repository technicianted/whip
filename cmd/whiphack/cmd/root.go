// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package cmd

import (
	"github.com/technicianted/whip/pkg/logging"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// RootCMD is the base command
var RootCMD = &cobra.Command{
	Use:   "whiphack",
	Short: "collection of hacking tools for whip",
}

var (
	logLevel string
)

func init() {
	RootCMD.PersistentFlags().StringVar(&logLevel, "log-level", "info", "set log level")
}

func SetLogging(logger logging.TraceLogger) {
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
