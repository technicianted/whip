// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.

package logging

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const requestIDLogField = "requestID"
const subsystemLogField = "subsystem"

// NewTraceLogger creates a new logger given a subsystem and UUID generated requestID.
func NewTraceLogger(subsystem string) TraceLogger {
	return NewTraceLoggerWithRequestID(subsystem, uuid.New().String())
}

// NewTraceLogger creates a new logger given a subsystem and UUID generated requestID.
func NewTraceLoggerFromLogger(subsystem string, logger TraceLogger) TraceLogger {
	id := uuid.UUID{}
	loggerID := GetRequestID(logger)
	if loggerID != "" {
		otherID, err := uuid.Parse(loggerID)
		if err == nil {
			id = otherID
		}
	}
	return NewTraceLoggerWithRequestID(subsystem, id.String())
}

// NewTraceLoggerWithRequestID creates a new logger with a subsystem and given requestID.
func NewTraceLoggerWithRequestID(subsystem string, requestID string) TraceLogger {
	return log.WithFields(log.Fields{
		requestIDLogField: requestID,
		subsystemLogField: subsystem,
	})
}

// GetRequestID returns the logger request ID.
func GetRequestID(logger TraceLogger) string {
	entry := logger.(*log.Entry)
	return entry.Data[requestIDLogField].(string)
}

func init() {
	log.SetFormatter(&LogFormatter{})
}
