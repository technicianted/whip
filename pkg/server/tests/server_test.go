// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/technicianted/whip/pkg/client"
	"github.com/technicianted/whip/pkg/logging"
	protov1 "github.com/technicianted/whip/pkg/proto/v1"
	"github.com/technicianted/whip/pkg/server"

	//lint:ignore SA1019 convenience of working with streams
	"github.com/golang/protobuf/jsonpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestServiceSimple(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	s := CreateNewServer(t)
	s.Start(t, logger)
	defer s.Stop(t, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	clientConn, err := grpc.DialContext(ctx,
		fmt.Sprintf(":%d", s.Options.GRPCListenPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	require.NoError(t, err)
	defer clientConn.Close()
	client := protov1.NewWhipClient(clientConn)
	stream, err := client.Register(ctx)
	require.NoError(t, err)
	err = stream.Send(&protov1.RequestStream{
		Stream: &protov1.RequestStream_Register{
			Register: &protov1.Register{
				Hostname: "testhost",
				Domain:   "testdomain",
				Ports:    []uint32{1234, 80},
			},
		},
	})
	require.NoError(t, err)

	testString := "hello world!"
	var conn net.Conn
	connectedChan := make(chan error)
	go func() {
		// artificially sleep to allow for previous message to be processed.
		time.Sleep(100 * time.Millisecond)
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancelDial()
		conn, err = s.DialContext(dialCtx, "tcp", "testhost.testdomain:80", logger)
		if err != nil {
			cancel()
			require.NoError(t, err)
		}
		defer conn.Close()
		close(connectedChan)
		_, err = conn.Write([]byte(testString))
		require.NoError(t, err)
	}()

	// read connection request
	msg, err := stream.Recv()
	require.NoError(t, err)

	connect := msg.GetConnect()
	require.NotNil(t, connect)
	require.Equal(t, s.Options.ExternalTCPHost, connect.Host)
	require.Equal(t, s.Options.ExternalTCPPort, int(connect.Port))
	require.Equal(t, 80, int(connect.LocalPort))

	// tcp connect
	tcpConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", connect.Host, connect.Port))
	require.NoError(t, err)
	defer tcpConn.Close()
	// send preamble
	m := new(jsonpb.Marshaler)
	err = m.Marshal(tcpConn, &protov1.ConnectionPreamble{
		ConnectionID: connect.ConnectionID,
	})
	require.NoError(t, err)

	// at this point we should get a connection
	select {
	case <-time.After(5 * time.Second):
		require.Fail(t, "timeout waiting for connection")
	case <-connectedChan:
	}
	// read from the socket
	bytes := make([]byte, 16)
	n, err := tcpConn.Read(bytes)
	require.NoError(t, err)
	require.Equal(t, len(testString), n)
	require.Equal(t, testString, string(bytes[0:n]))
}

func TestServiceRemoteError(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	s := CreateNewServer(t)
	s.Start(t, logger)
	defer s.Stop(t, logger)

	client := client.NewClient(client.ClientOptions{
		WhipServiceEndpoints: []string{fmt.Sprintf("127.0.0.1:%d", s.Options.GRPCListenPort)},
		Hostname:             "testhost",
		Domain:               "testdomain",
		Ports:                []int{1234, 80},
	})
	err := client.Start(logger)
	require.NoError(t, err)
	defer client.Stop(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = s.DialContext(ctx, "tcp", "testhost.testdomain:80", logger, server.WithWaitForHost(true))
	require.Error(t, err)
	require.True(t, server.IsRemoteError(err), "unexpected error: %v", err)
}
