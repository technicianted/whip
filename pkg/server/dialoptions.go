// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package server

import "github.com/technicianted/whip/pkg/types"

type dialOptions struct {
	waitForResolve bool
}

func newDialOptions(opts []types.DialOption) *dialOptions {
	o := &dialOptions{}
	for _, opt := range opts {
		opt(o)
	}

	return o
}

// WithWaitForHost returns a dial option that would block DialContext call until the target host
// is available or context is cancelled. Default is false which means immediately fail if the host
// has not already registered.
func WithWaitForHost(w bool) types.DialOption {
	return func(o interface{}) {
		if opt, ok := o.(*dialOptions); ok {
			opt.waitForResolve = w
		}
	}
}
