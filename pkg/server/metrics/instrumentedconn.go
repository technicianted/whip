package metrics

import (
	"net"
	"strconv"
	"time"
)

var _ net.Conn = &InstrumentedConn{}

// InstrumentedConn is a wrapper around net.Conn that adds instrumentation.
type InstrumentedConn struct {
	net.Conn
	domain string
	port   string
}

func NewInstrumentedConn(conn net.Conn, domain string, port int) *InstrumentedConn {
	strPort := strconv.Itoa(port)
	ActiveConnections.WithLabelValues(domain, strPort).Inc()

	return &InstrumentedConn{
		Conn:   conn,
		domain: domain,
		port:   strPort,
	}
}

func (c *InstrumentedConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *InstrumentedConn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

func (c *InstrumentedConn) Close() error {
	ActiveConnections.WithLabelValues(c.domain, c.port).Inc()
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
