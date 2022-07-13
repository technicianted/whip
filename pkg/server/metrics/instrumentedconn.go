package metrics

import (
	"net"
	"strconv"
	"time"

	"github.com/technicianted/whip/pkg/logging"
)

var _ net.Conn = &InstrumentedConn{}

// InstrumentedConn is a wrapper around net.Conn that adds instrumentation.
type InstrumentedConn struct {
	net.Conn
	domain string
	port   string
	logger logging.TraceLogger
}

func NewInstrumentedConn(conn net.Conn, domain string, port int, logger logging.TraceLogger) *InstrumentedConn {
	strPort := strconv.Itoa(port)
	ActiveConnections.WithLabelValues(domain, strPort).Inc()

	logger.Tracef("instrumented connection created")
	return &InstrumentedConn{
		Conn:   conn,
		domain: domain,
		port:   strPort,
		logger: logging.NewTraceLoggerFromLogger("tcpconn", logger),
	}
}

func (c *InstrumentedConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *InstrumentedConn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

func (c *InstrumentedConn) Close() error {
	ActiveConnections.WithLabelValues(c.domain, c.port).Dec()
	c.logger.Tracef("connection closed")
	return c.Conn.Close()
}

func (c *InstrumentedConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *InstrumentedConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *InstrumentedConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *InstrumentedConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *InstrumentedConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
