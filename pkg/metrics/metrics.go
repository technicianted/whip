// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package metrics

import (
	"net/http"
	"strings"

	"github.com/technicianted/whip/pkg/logging"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	Namespace = "whip"

	DomainLabel = "domain"
	PortLabel   = "port"
)

// StartMetricsExposer starts prometheus metrics exposer
func StartMetricsExposer(address string, logger logging.TraceLogger) {
	path := "/metrics"
	index := strings.Index(address, "/")
	if index != -1 {
		path = address[index:]
		address = address[0:index]
	}
	http.Handle(path, promhttp.Handler())
	go func() {
		logger.Infof("starting prometheus exposer: %s", address)
		err := http.ListenAndServe(address, nil)
		logger.Warnf("prometheus metrics exposer terminated: %v", err)
	}()
}
