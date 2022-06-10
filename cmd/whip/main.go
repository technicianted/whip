// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package main

import (
	"fmt"
	"os"

	"github.com/technicianted/whip/cmd/whip/cmd"
	_ "github.com/technicianted/whip/cmd/whip/cmd/client"
	_ "github.com/technicianted/whip/cmd/whip/cmd/proxy"
)

func main() {
	if err := cmd.RootCMD.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
