// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package main

import (
	"fmt"
	"os"

	"github.com/technicianted/whip/cmd/whiphack/cmd"
	_ "github.com/technicianted/whip/cmd/whiphack/cmd/pki"
	_ "github.com/technicianted/whip/cmd/whiphack/cmd/pki/createandsign"
)

func main() {
	if err := cmd.RootCMD.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
