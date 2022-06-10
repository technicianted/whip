// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package metrics

import (
	metricscommon "github.com/technicianted/whip/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	Subsystem = "client"
)

var (
	ActiveConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricscommon.Namespace,
			Subsystem: Subsystem,
			Name:      "active_connections",
			Help:      "Active proxied connections",
		},
		[]string{metricscommon.DomainLabel, metricscommon.PortLabel},
	)
)
