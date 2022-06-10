// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package proxy

import (
	"context"
	"net"

	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/types"
)

var _ types.Dialer = &FallbackDialer{}

// FallbackDialer is an implementation of types.Dialer that would first try out
// one dialer and if it fails, it dials using net.Dialer.
type FallbackDialer struct {
	defaultOptions []types.DialOption
	dialer         types.Dialer
	netDialer      net.Dialer
}

// NewFallbackDialer creates a new dialer that tries out innerDialer with opts. If it fails,
// it falls back to using net.Dialer.
func NewFallbackDialer(innerDialer types.Dialer, opts ...types.DialOption) *FallbackDialer {
	return &FallbackDialer{
		defaultOptions: opts,
		dialer:         innerDialer,
	}
}

// DialContext implements types.Dialer
func (d *FallbackDialer) DialContext(ctx context.Context, network, address string, logger logging.TraceLogger, opts ...types.DialOption) (net.Conn, error) {
	logger = logging.NewTraceLoggerFromLogger("fallbackdialer", logger)

	mergedOptions := append(d.defaultOptions, opts...)
	logger.Tracef("dialing primary dialer")
	conn, err := d.dialer.DialContext(ctx, network, address, logger, mergedOptions...)
	if err == nil {
		logger.Tracef("primary dialer succeeded")
		return conn, nil
	}

	if ctx.Err() != nil {
		logger.Tracef("context cancelled")
		return nil, err
	}

	logger.Tracef("primary dialer failed, dialing net: %v", err)
	return d.netDialer.DialContext(ctx, network, address)
}
