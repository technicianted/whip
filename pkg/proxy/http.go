// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/proxy/metrics"
	"github.com/technicianted/whip/pkg/types"
)

type requestIDType string

const (
	requestIDContextKey requestIDType = "whiprequestid"
)

const (
	UpstreamRequestIDHeader = "whip-request-id"
)

// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

var _ http.Handler = &HTTP{}

// HTTP is a simple http handler proxy that uses whip dialer to dial out upstream
// proxied requests.
type HTTP struct {
	dialer                    types.Dialer
	downstreamRequestIDheader string
	httpClient                http.Client
}

// NewHTTP creates a new proxy with whip dialer. It tries to correlates downstream requests
// using given downstreamRequestIDHeader.
func NewHTTP(dialer types.Dialer, downstreamRequestIDheader string) *HTTP {
	return &HTTP{
		dialer:                    dialer,
		downstreamRequestIDheader: downstreamRequestIDheader,
		httpClient: http.Client{
			Transport: &http.Transport{
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
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *HTTP) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	var logger logging.TraceLogger
	if requestID := req.Header.Get(p.downstreamRequestIDheader); p.downstreamRequestIDheader != "" && requestID != "" {
		logger = logging.NewTraceLoggerWithRequestID("proxy", requestID)
	} else {
		logger = logging.NewTraceLogger("proxy")
	}

	logger.Tracef("new request: %v: %s: %v", req.RemoteAddr, req.Method, req.URL)

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		msg := fmt.Sprintf("unsupported protocol scheme: %v", req.URL.Scheme)
		http.Error(wr, msg, http.StatusBadRequest)
		logger.Errorf(msg)
		return
	}

	if remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		p.appendHostToXForwardHeader(req.Header, remoteAddr)
	}

	logger.Tracef("performing upstream request")
	p.deleteHopHeaders(req.Header)

	requestContext := context.WithValue(req.Context(), requestIDContextKey, logging.GetRequestID(logger))
	req = req.WithContext(requestContext)
	req.RequestURI = ""
	resp, err := p.httpClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("upstream error: %v", err)
		http.Error(wr, msg, http.StatusBadGateway)
		logger.Errorf(msg)
		metrics.RequestsTotal.WithLabelValues("", "true").Inc()
		return
	}
	defer resp.Body.Close()

	metrics.RequestsTotal.WithLabelValues(strconv.Itoa(resp.StatusCode), "").Inc()

	logger.Tracef("response: %s", resp.Status)
	// process headers
	p.deleteHopHeaders(resp.Header)
	for header, values := range resp.Header {
		for _, value := range values {
			wr.Header().Add(header, value)
		}
	}

	wr.WriteHeader(resp.StatusCode)
	if f, ok := wr.(http.Flusher); ok {
		f.Flush()
	}

	io.Copy(wr, resp.Body)
}

func (p *HTTP) appendHostToXForwardHeader(header http.Header, host string) {
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func (p *HTTP) deleteHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}
