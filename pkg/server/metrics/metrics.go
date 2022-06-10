// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package metrics

import (
	metricscommon "github.com/technicianted/whip/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	Subsystem = "server"

	OpLabel                = "op"
	OpTCPConnectionResolve = "resolve"
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

	ActiveRegistrations = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricscommon.Namespace,
			Subsystem: Subsystem,
			Name:      "active_registrations",
			Help:      "Active number of registered clients",
		},
		[]string{metricscommon.DomainLabel},
	)

	ClientRoundTripLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricscommon.Namespace,
			Subsystem: Subsystem,
			Name:      "client_round_trip_latency",
			Help:      "Client response latency as measured on control grpc",
			Buckets:   prometheus.ExponentialBucketsRange(0.001, 1.0, 10),
		},
		[]string{metricscommon.DomainLabel},
	)

	TCPConnectionLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricscommon.Namespace,
			Subsystem: Subsystem,
			Name:      "tcp_connection_latency",
			Help:      "Latency of creating new tcp connection to remote client",
			Buckets:   prometheus.ExponentialBucketsRange(0.001, 1.0, 10),
		},
		[]string{metricscommon.DomainLabel, OpLabel},
	)
)
