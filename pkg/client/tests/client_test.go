// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/technicianted/whip/pkg/client"
	"github.com/technicianted/whip/pkg/logging"
	"github.com/technicianted/whip/pkg/server"
	servertesting "github.com/technicianted/whip/pkg/server/tests"

	"github.com/stretchr/testify/require"
)

func TestClientSimple(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	testString := "hello, world!"
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testString)
	}))
	u, err := url.Parse(httpServer.URL)
	require.NoError(t, err)
	localPort, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	serv := servertesting.CreateNewServer(t)
	serv.Start(t, logger)
	defer serv.Stop(t, logger)

	options := client.ClientOptions{
		WhipServiceEndpoints: []string{fmt.Sprintf("127.0.0.1:%d", serv.Options.GRPCListenPort)},
		Hostname:             "testhost",
		Domain:               "testdomain",
		Ports:                []int{localPort},
	}
	client := client.NewClient(options)
	err = client.Start(logger)
	require.NoError(t, err)
	defer client.Stop(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	conn, err := serv.DialContext(ctx, "tcp", fmt.Sprintf("testhost.testdomain:%d", localPort), logger, server.WithWaitForHost(true))
	require.NoError(t, err)
	defer conn.Close()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://testhost.testdomain:%d", localPort), nil)
	require.NoError(t, err)
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, testString, string(body))
}
