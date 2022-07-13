// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/proxy/metrics"
	"github.com/technicianted/whip/pkg/types"
)

// SingleHost is an http proxy that forwards all requests to a pre-set host.
type SingleHost struct {
	dialer                    types.Dialer
	reverseProxy              *httputil.ReverseProxy
	username                  string
	password                  string
	downstreamRequestIDheader string
}

// NewSingleHost creates a new single host proxy that uses whip dialer to target.
func NewSingleHost(dialer types.Dialer, downstreamRequestIDheader, username, password string, target *url.URL) *SingleHost {
	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	reverseProxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var logger logging.TraceLogger
			requestIDValue := ctx.Value(requestIDContextKey)
			if requestID, ok := requestIDValue.(string); ok && requestID != "" {
				logger = logging.NewTraceLoggerWithRequestID("proxyclient", requestID)
			} else {
				logger = logging.NewTraceLogger("proxyclient")
			}
			return dialer.DialContext(ctx, network, addr, logger)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	reverseProxy.FlushInterval = -1
	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		metrics.RequestsTotal.WithLabelValues(resp.Proto, strconv.Itoa(resp.StatusCode), "").Inc()
		return nil
	}
	reverseProxy.ErrorHandler = func(wr http.ResponseWriter, req *http.Request, err error) {
		metrics.RequestsTotal.WithLabelValues(req.Proto, "", "upstream_failed").Inc()
	}

	return &SingleHost{
		dialer:                    dialer,
		reverseProxy:              reverseProxy,
		downstreamRequestIDheader: downstreamRequestIDheader,
		username:                  username,
		password:                  password,
	}
}

func (p *SingleHost) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	var logger logging.TraceLogger
	if requestID := req.Header.Get(p.downstreamRequestIDheader); p.downstreamRequestIDheader != "" && requestID != "" {
		logger = logging.NewTraceLoggerWithRequestID("proxy", requestID)
	} else {
		logger = logging.NewTraceLogger("proxy")
	}

	logger.Tracef("new request: %v: %s: %v", req.RemoteAddr, req.Method, req.URL)

	if !checkAuth(req.Header["Proxy-Authorization"], p.username, p.password, logger) {
		msg := "authentication failed"
		http.Error(wr, msg, http.StatusUnauthorized)
		logger.Errorf(msg)
		return
	}

	requestContext := context.WithValue(req.Context(), requestIDContextKey, logging.GetRequestID(logger))
	req = req.WithContext(requestContext)

	p.reverseProxy.ServeHTTP(wr, req)
}
