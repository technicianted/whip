// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	username                  string
	password                  string
	downstreamRequestIDheader string
	httpClient                http.Client
}

// NewHTTP creates a new proxy with whip dialer. It tries to correlates downstream requests
// using given downstreamRequestIDHeader.
func NewHTTP(dialer types.Dialer, downstreamRequestIDheader, username, password string) *HTTP {
	return &HTTP{
		dialer:                    dialer,
		username:                  username,
		password:                  password,
		downstreamRequestIDheader: downstreamRequestIDheader,
		httpClient: http.Client{
			Transport: &http.Transport{
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
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *HTTP) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	requestStartTime := time.Now()

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

	if !checkAuth(req.Header["Proxy-Authorization"], p.username, p.password, logger) {
		msg := "authentication failed"
		http.Error(wr, msg, http.StatusUnauthorized)
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
		metrics.RequestsTotal.WithLabelValues(req.Proto, "", "true").Inc()
		return
	}

	defer resp.Body.Close()

	metrics.RequestsTotal.WithLabelValues(req.Proto, strconv.Itoa(resp.StatusCode), "").Inc()

	logger.Tracef("response: %s", resp.Status)
	// process headers
	p.deleteHopHeaders(resp.Header)
	for header, values := range resp.Header {
		for _, value := range values {
			wr.Header().Add(header, value)
		}
	}

	wr.Header()["whip_proxy_request_time"] = []string{fmt.Sprintf("%v", requestStartTime)}
	wr.Header()["whip_proxy_response_time"] = []string{fmt.Sprintf("%v", time.Now())}
	wr.WriteHeader(resp.StatusCode)
	if f, ok := wr.(http.Flusher); ok {
		f.Flush()
	}

	buffer := make([]byte, 32*1024)
	for {
		logger.Trace("reading from client")
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			logger.Tracef("read: %s", string(buffer[0:n]))
			nw, err := wr.Write(buffer[0:n])
			if nw != n {
				logger.Warnf("short write: %d != %d", nw, n)
				return
			}
			if err != nil {
				logger.Warnf("failed to write to client: %v", err)
				return
			}
			logger.Tracef("wrote: %d", nw)
			if f, ok := wr.(http.Flusher); ok {
				f.Flush()
			}
			logger.Tracef("flushed")
		}
		if err != nil {
			break
		}
	}
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
