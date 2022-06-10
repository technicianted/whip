// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package metrics

import (
	metricscommon "github.com/technicianted/whip/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	Subsystem = "http_proxy"

	HTTPStatusLabel = "status"
	ErrorLabel      = "error"
)

var (
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricscommon.Namespace,
			Subsystem: Subsystem,
			Name:      "requests_total",
			Help:      "Total requests proxied http requests",
		},
		[]string{HTTPStatusLabel, ErrorLabel},
	)
)
