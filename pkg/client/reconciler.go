// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/technicianted/whip/pkg/client/types"
	"github.com/technicianted/whip/pkg/logging"
)

var _ types.ClientReconciler = &reconciler{}

// reconciler is a concrete implementation of types.ClientReconciler that continuously
// monitors the state of whip service endpoints for new or removed clients.
// It uses the provided types.WhipEndpointResolver to discover changes in endpoints
// and returns reconciliation steps.
type reconciler struct {
	resolver types.WhipEndpointResolver
}

// newReconciler creates a new reconciler with the given resolver. The resolver will
// be used on every iteration to discover changes to endpoints.
func newReconciler(resolver types.WhipEndpointResolver) *reconciler {
	return &reconciler{
		resolver: resolver,
	}
}

// Reconcile performs a single reconciliation pass on endpoints. For each endpoint:
// * use provider types.WhipEndpointResolver to discover if new ip addresses have been added,
//   removed or if the endpoint no longer exists.
// * reconcile the new state of the endpoint with the given currentClientKeys.
// * return deltas that the caller needs to apply to get the goal state.
//
// If the resolver returns a temporary dns failure error, the client keys will not be deleted
// until a permanent resolution failure is returned.
func (r *reconciler) Reconcile(ctx context.Context, endpoints []string, currentClientKeys []string, logger logging.TraceLogger) (removedClients []string, addedClients []types.ReconcilerClientInfo, err error) {
	existingClients := []string{}
	for _, endpoint := range endpoints {
		existing, removed, added, err := r.reconcileEndpoint(ctx, endpoint, currentClientKeys, logger)
		if err != nil {
			return nil, nil, err
		}
		existingClients = append(existingClients, existing...)
		removedClients = append(removedClients, removed...)
		addedClients = append(addedClients, added...)
	}

	// remove the remaining ones
	handled := map[string]bool{}
	for _, key := range append(existingClients, removedClients...) {
		handled[key] = true
	}
	for _, key := range currentClientKeys {
		if _, ok := handled[key]; !ok {
			removedClients = append(removedClients, key)
		}
	}

	return
}

func (r *reconciler) reconcileEndpoint(ctx context.Context, endpoint string, currentClientKeys []string, logger logging.TraceLogger) (existingClients []string, removedClients []string, addedClients []types.ReconcilerClientInfo, err error) {
	u, err := r.parseEndpoint(endpoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse endpoint %s: %v", endpoint, err)
	}

	hostname := u.Hostname()
	logger.Debugf("attempting to resolve host %s for endpoint %s", hostname, endpoint)
	addresses, err := r.resolver.Resolve(ctx, hostname)
	if err != nil {
		if dnsError, ok := err.(*net.DNSError); ok {
			if dnsError.IsNotFound {
				logger.Warnf("endpoint %s host not found: %v", endpoint, err)
				for _, key := range currentClientKeys {
					if r.keyEndpointMatch(key, endpoint) {
						removedClients = append(removedClients, key)
					}
				}
				err = nil
				return
			}
		}
		logger.Warnf("temporary failure resolving host %s", hostname)
		for _, key := range currentClientKeys {
			if r.keyEndpointMatch(key, endpoint) {
				existingClients = append(existingClients, key)
			}
		}
		err = nil
		return
	}

	logger.Debugf("resolved endpoint %s, host %s to: %v", endpoint, hostname, addresses)
	currentKeyMap := map[string]bool{}
	for _, key := range currentClientKeys {
		currentKeyMap[key] = true
	}
	for _, ipAddress := range addresses {
		client := types.ReconcilerClientInfo{
			Endpoint:  endpoint,
			Hostname:  hostname,
			Port:      u.Port(),
			Authority: u.Host,
			IPAddress: ipAddress,
		}
		client.Key = r.clientKey(client)

		if _, ok := currentKeyMap[client.Key]; ok {
			logger.Debugf("skipping endpoint %s ip %s already exists", endpoint, ipAddress)
			existingClients = append(existingClients, client.Key)
			continue
		}

		logger.Infof("adding new address %s for endpoint %s", ipAddress, endpoint)
		addedClients = append(addedClients, client)
	}

	return
}

func (r *reconciler) clientKey(c types.ReconcilerClientInfo) string {
	return fmt.Sprintf("%s$%s", c.Endpoint, c.IPAddress)
}

func (r *reconciler) keyEndpointMatch(key, endpoint string) bool {
	parts := strings.Split(key, "$")
	return parts[0] == endpoint
}

func (r *reconciler) parseEndpoint(endpoint string) (*url.URL, error) {
	// for traditional grpc endpoints like localhost:8080, url.Parse
	// is not going to work as expected so we need to prepend a dummy
	// https:// prefix to force it to parse it as a host.
	u, err := url.Parse(endpoint)
	if err == nil && u.Scheme != "" {
		return u, nil
	}

	endpoint = "https://" + endpoint
	return url.Parse(endpoint)
}
