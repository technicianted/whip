// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package types

import (
	"context"
	"net"

	"github.com/technicianted/whip/pkg/logging"
)

// DialOption represents a generic DialContext option. Implementations can provider their own.
type DialOption func(interface{})

// Dialer is an interface representing a whip dialer. In normal cases it is either server.Server or
// server.Service.
type Dialer interface {
	// DialContext dials address with opts via whip service. It requests the establishment of a reverse
	// tcp connection to address.
	// Addresses DialContext calls are "resolved" against already registered remote clients based
	// on their host and domain as follows:
	// * If DialContext address matches exactly host.domain client then it is used.
	// * If not, if DialContext address matches exactly a domain of 1 or more clients, one is
	//   picked up at random.
	//
	// It returns net.DNSError if address does not resolve to any registered clients.
	DialContext(ctx context.Context, network, address string, logger logging.TraceLogger, opts ...DialOption) (net.Conn, error)
}
