// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/technicianted/whip/pkg/client/metrics"
	"github.com/technicianted/whip/pkg/client/types"
	"github.com/technicianted/whip/pkg/logging"
	protov1 "github.com/technicianted/whip/pkg/proto/v1"

	"github.com/cenkalti/backoff"
	//lint:ignore SA1019 convenience of working with streams
	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WhipClient is a client that connects to whip control service to coordinate
// establishment of reverse tcp tunnels. It first registers itself with the control
// service using given hostname and domain (its name becomes hostname.domain) then
// waits for tcp connect control messages (see protos). When it receives one, it
// establishes a reverse tcp connection to the whip control service and begins
// proxying it to the local requested port.
type WhipClient struct {
	whipClientConn *grpc.ClientConn
	tcpConnDialer  types.ClientConnDialer
	hostname       string
	domain         string
	ports          []uint32

	callCancel      context.CancelFunc
	callStoppedChan chan interface{}
	proxyWG         sync.WaitGroup
}

// NewWhipClient creates a new client connecting to whip control service using whipClientConn and
// dials tcp connections back to whip service using tcpConnDialer. It registers itself with whip
// control service as hostname and domain (hostname.domain becomes its known name) and publishes
// ports that can be used for reverse tunnels.
func NewWhipClient(whipClientConn *grpc.ClientConn, tcpConnDialer types.ClientConnDialer, hostname, domain string, ports []int) *WhipClient {
	intPorts := make([]uint32, len(ports))
	for i, port := range ports {
		intPorts[i] = uint32(port)
	}
	return &WhipClient{
		whipClientConn: whipClientConn,
		tcpConnDialer:  tcpConnDialer,
		hostname:       hostname,
		domain:         domain,
		ports:          intPorts,
	}
}

// Start starts the whip client. It returns immediately before connection to whip service
// is established.
func (c *WhipClient) Start(logger logging.TraceLogger) error {
	logger.Infof("starting whip client")

	c.callStoppedChan = make(chan interface{})
	ctx, cancel := context.WithCancel(context.Background())
	c.callCancel = cancel
	go c.whipServiceLoop(ctx, logger)

	return nil
}

// Stop stops this client instance disconnecting from whip service and disconnecting all currently
// established reverse tunnels.
// The function will block until all connections are terminated.
func (c *WhipClient) Stop(logger logging.TraceLogger) error {
	logger.Infof("stopping whip client")

	if c.callCancel != nil {
		c.callCancel()
	}
	logger.Infof("waiting for whip grpc to terminate")
	<-c.callStoppedChan
	logger.Infof("waiting for proxies to terminate")
	c.proxyWG.Wait()

	return nil
}

func (c *WhipClient) whipServiceLoop(ctx context.Context, logger logging.TraceLogger) {
	logger = logging.NewTraceLoggerFromLogger("grpc", logger)
	for {
		stream, err := c.regsiterWhip(ctx, logger)
		if err != nil {
			logger.Errorf("failed to register with whip: %v", err)
			break
		}

		for {
			msg, err := stream.Recv()
			if err != nil {
				logger.Errorf("failed to receive: %v", err)
				break
			}

			switch resp := msg.Stream.(type) {
			case *protov1.ResponseStream_Ping:
				logger.Tracef("ping? pong!")
				pong := &protov1.RequestStream{
					Stream: &protov1.RequestStream_Pong{
						Pong: &protov1.Pong{
							Sequence:      resp.Ping.Sequence,
							PingTimestamp: resp.Ping.PingTimestamp,
							PongTimestamp: timestamppb.Now(),
						},
					},
				}
				if err := stream.Send(pong); err != nil {
					logger.Errorf("failed to send pong: %v", err)
					break
				}
			case *protov1.ResponseStream_Connect:
				go c.handleConnect(ctx, resp.Connect, stream, logger)
			}
		}

		time.Sleep(5 * time.Second)
	}

	close(c.callStoppedChan)
}

func (c *WhipClient) handleConnect(ctx context.Context, msg *protov1.Connect, stream protov1.Whip_RegisterClient, logger logging.TraceLogger) {
	logger.Infof("received connect request: %v", msg)
	logger = logging.NewTraceLoggerWithRequestID("tcp", msg.ConnectionID)

	metrics.ActiveConnections.WithLabelValues(c.domain, fmt.Sprintf("%d", msg.Port)).Inc()
	defer metrics.ActiveConnections.WithLabelValues(c.domain, fmt.Sprintf("%d", msg.Port)).Dec()

	c.proxyWG.Add(1)
	defer c.proxyWG.Done()

	localAddress := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(msg.LocalPort), 10))
	logger.Infof("starting local connection to: %s", localAddress)
	localConn, err := net.Dial("tcp", localAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to local connect to %s: %v", localAddress, err)
		logger.Errorf(errorMessage)
		stream.Send(&protov1.RequestStream{
			Stream: &protov1.RequestStream_ConnectFailed{
				ConnectFailed: &protov1.ConnectFailed{
					ConnectionID: msg.ConnectionID,
					ErrorMessage: errorMessage,
				},
			},
		})
		return
	}
	defer localConn.Close()

	tcpAddress := net.JoinHostPort(msg.Host, strconv.FormatUint(uint64(msg.Port), 10))
	logger.Tracef("connecting to: %v", tcpAddress)
	conn, err := c.tcpConnDialer.DialContext(ctx, "tcp", tcpAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to connect to %s: %v", tcpAddress, err)
		logger.Errorf(errorMessage)
		stream.Send(&protov1.RequestStream{
			Stream: &protov1.RequestStream_ConnectFailed{
				ConnectFailed: &protov1.ConnectFailed{
					ConnectionID: msg.ConnectionID,
					ErrorMessage: errorMessage,
				},
			},
		})
		return
	}
	defer conn.Close()

	logger.Infof("sending preamble")
	m := new(jsonpb.Marshaler)
	err = m.Marshal(conn, &protov1.ConnectionPreamble{
		ConnectionID: msg.ConnectionID,
	})
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send preamble: %v", err)
		logger.Errorf(errorMessage)
		stream.Send(&protov1.RequestStream{
			Stream: &protov1.RequestStream_ConnectFailed{
				ConnectFailed: &protov1.ConnectFailed{
					ConnectionID: msg.ConnectionID,
					ErrorMessage: errorMessage,
				},
			},
		})
		return
	}

	logger.Infof("starting tcp proxy")
	localReaderDoneChan := make(chan interface{})
	remoteReaderDoneChan := make(chan interface{})
	go func() {
		buffer := make([]byte, 32*1024*1024)
		for {
			n, err := localConn.Read(buffer)
			if err != nil {
				logger.Errorf("failed to do local read: %v", err)
				break
			}
			wn, err := conn.Write(buffer[0:n])
			if err != nil {
				logger.Errorf("failed to copy local: %v", err)
				break
			}
			if wn != n {
				logger.Errorf("short write to remote: %d != %d", wn, n)
				break
			}
		}
		close(localReaderDoneChan)
	}()
	go func() {
		buffer := make([]byte, 32*1024*1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				logger.Errorf("failed to do remote read: %v", err)
				break
			}
			wn, err := localConn.Write(buffer[0:n])
			if err != nil {
				logger.Errorf("failed to copy remote: %v", err)
				break
			}
			if wn != n {
				logger.Errorf("short write to local: %d != %d", wn, n)
				break
			}
		}
		close(remoteReaderDoneChan)
	}()

	// if any of the go routines fail, cleanup immediately
	select {
	case <-localReaderDoneChan:
	case <-remoteReaderDoneChan:
	case <-ctx.Done():
	}

	logger.Debugf("tcp proxy exiting")
}

func (c *WhipClient) regsiterWhip(ctx context.Context, logger logging.TraceLogger) (protov1.Whip_RegisterClient, error) {
	var whipGRPCClient protov1.WhipClient
	var stream protov1.Whip_RegisterClient
	startStreamFunc := func() (err error) {
		logger.Infof("starting registration with whip service")
		whipGRPCClient = protov1.NewWhipClient(c.whipClientConn)
		stream, err = whipGRPCClient.Register(ctx)
		if err != nil {
			logger.Errorf("failed to register: %v", err)
			if ctx.Err() != nil {
				err = &backoff.PermanentError{Err: err}
			}
			return
		}

		registerMessage := &protov1.RequestStream{
			Stream: &protov1.RequestStream_Register{
				Register: &protov1.Register{
					Hostname: c.hostname,
					Domain:   c.domain,
					Ports:    c.ports,
				},
			},
		}
		err = stream.Send(registerMessage)
		if err != nil {
			logger.Errorf("failed to send registration: %v", err)
			stream.CloseSend()
		}

		return
	}

	expBackoff := backoff.NewExponentialBackOff()
	err := backoff.Retry(startStreamFunc, expBackoff)
	if err != nil {
		return nil, err
	}

	return stream, nil
}
