// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"net"
	"testing"

	"github.com/technicianted/whip/pkg/client/mocks"
	"github.com/technicianted/whip/pkg/logging"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestClientReconcilerNewEndpoints(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return([]string{"1.1.1.1", "2.2.2.2"}, nil)
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{},
		logger)
	require.NoError(t, err)
	require.Len(t, removed, 0)
	require.Len(t, added, 3)
	require.Equal(t, "test1.endpoint$1.1.1.1", added[0].Key)
	require.Equal(t, "test1.endpoint$2.2.2.2", added[1].Key)
	require.Equal(t, "test2.endpoint$3.3.3.3", added[2].Key)
}

func TestClientReconcilerNoChange(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return([]string{"1.1.1.1", "2.2.2.2"}, nil)
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test1.endpoint$2.2.2.2", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, removed, 0)
	require.Len(t, added, 0)
}

func TestClientReconcilerRemovedEndpoint(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test1.endpoint$2.2.2.2", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, removed, 2)
	require.Len(t, added, 0)
	require.Equal(t, "test1.endpoint$1.1.1.1", removed[0])
	require.Equal(t, "test1.endpoint$2.2.2.2", removed[1])
}

func TestClientReconcilerAddressRemoved(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return([]string{"1.1.1.1"}, nil)
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test1.endpoint$2.2.2.2", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, removed, 1)
	require.Len(t, added, 0)
	require.Equal(t, "test1.endpoint$2.2.2.2", removed[0])
}

func TestClientReconcilerAddressAdded(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return([]string{"1.1.1.1", "2.2.2.2"}, nil)
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, removed, 0)
	require.Len(t, added, 1)
	require.Equal(t, "test1.endpoint$2.2.2.2", added[0].Key)
}

func TestClientReconcilerHostPermanentFailure(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return(nil, &net.DNSError{IsNotFound: true})
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test1.endpoint$2.2.2.2", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, added, 0)
	require.Len(t, removed, 2)
	require.Equal(t, "test1.endpoint$1.1.1.1", removed[0])
	require.Equal(t, "test1.endpoint$2.2.2.2", removed[1])
}

func TestClientReconcilerHostTemporaryFailure(t *testing.T) {
	logger := logging.NewTraceLogger(t.Name())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	resolver := mocks.NewMockWhipEndpointResolver(mockCtrl)
	recon := newReconciler(resolver)

	resolver.EXPECT().Resolve(gomock.Any(), "test1.endpoint").Return(nil, &net.DNSError{IsTemporary: true})
	resolver.EXPECT().Resolve(gomock.Any(), "test2.endpoint").Return([]string{"3.3.3.3"}, nil)
	removed, added, err := recon.Reconcile(
		context.Background(),
		[]string{"test1.endpoint", "test2.endpoint"},
		[]string{"test1.endpoint$1.1.1.1", "test1.endpoint$2.2.2.2", "test2.endpoint$3.3.3.3"},
		logger)
	require.NoError(t, err)
	require.Len(t, added, 0)
	require.Len(t, removed, 0)
}

func TestURLParser(t *testing.T) {
	u, err := parseEndpoint("test1.endpoint.com")
	require.NoError(t, err)
	require.Equal(t, "test1.endpoint.com", u.Hostname())

	u, err = parseEndpoint("test1.endpoint.com:1234")
	require.NoError(t, err)
	require.Equal(t, "test1.endpoint.com:1234", u.Host)
	require.Equal(t, "test1.endpoint.com", u.Hostname())
}
