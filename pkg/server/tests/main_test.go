// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tests

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.TraceLevel)

	os.Exit(m.Run())
}
