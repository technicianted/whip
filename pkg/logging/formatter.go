// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.

package logging

import (
	"bytes"
	"fmt"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// LogFormatter is a custom standard formatter.
// It implements logrus.Formatter interface.
// Note that the formatter is automatically registered by default.
type LogFormatter struct{}

// NewLogFormatter creates a new trace logging output formatter.
// Note that the formatter is automatically registered by default.
func NewLogFormatter() *LogFormatter {
	return &LogFormatter{}
}

// Register sets the formatter in the log system.
// Note that the formatter is automatically registered by default.
func (formatter *LogFormatter) Register() {
	log.SetFormatter(formatter)
}

// Format perform custom logger formatting.
func (formatter *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	b.WriteString(fmt.Sprintf("%-29s", entry.Time.Format("2006-01-02T15:04:05.999999-07:00")))
	b.WriteString(" ")
	requestID, ok := entry.Data["requestID"].(string)
	if !ok || requestID == "" {
		requestID = uuid.Nil.String()
	}
	b.WriteString(requestID)
	b.WriteString(" ")
	subsystem, ok := entry.Data["subsystem"]
	if !ok {
		subsystem = "unknown"
	}
	b.WriteString(fmt.Sprintf("%-20s", subsystem))
	b.WriteString(fmt.Sprintf("%-5s", entry.Level.String()))
	b.WriteString(" ")
	b.WriteString(entry.Message)
	b.WriteString("\n")

	return b.Bytes(), nil
}
