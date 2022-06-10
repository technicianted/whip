// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.

package logging

import (
	log "github.com/sirupsen/logrus"
)

type Level = log.Level

const (
	PanicLevel Level = Level(log.PanicLevel)
	FatalLevel Level = Level(log.FatalLevel)
	ErrorLevel Level = Level(log.ErrorLevel)
	WarnLevel  Level = Level(log.WarnLevel)
	InfoLevel  Level = Level(log.InfoLevel)
	DebugLevel Level = Level(log.DebugLevel)
	TraceLevel Level = Level(log.TraceLevel)
)

// TraceLogger is an interface for a logger that can be used for
// tracing using an identifer.
type TraceLogger interface {
	Log(level Level, args ...interface{})

	// Trace logs a message at level Trace.
	Trace(args ...interface{})

	// Debug logs a message at level Debug.
	Debug(args ...interface{})

	// Print logs a message at level Info.
	Print(args ...interface{})

	// Info logs a message at level Info.
	Info(args ...interface{})

	// Warn logs a message at level Warn.
	Warn(args ...interface{})

	// Warning logs a message at level Warn.
	Warning(args ...interface{})

	// Error logs a message at level Error.
	Error(args ...interface{})

	// Panic logs a message at level Panic.
	Panic(args ...interface{})

	// Fatal logs a message at level Fatal.
	Fatal(args ...interface{})

	Logf(level Level, format string, args ...interface{})

	// Tracef logs a message at level Trace.
	Tracef(format string, args ...interface{})

	// Debugf logs a message at level Debug.
	Debugf(format string, args ...interface{})

	// Printf logs a message at level Info.
	Printf(format string, args ...interface{})

	// Infof logs a message at level Info.
	Infof(format string, args ...interface{})

	// Warnf logs a message at level Warn.
	Warnf(format string, args ...interface{})

	// Warningf logs a message at level Warn.
	Warningf(format string, args ...interface{})

	// Errorf logs a message at level Error.
	Errorf(format string, args ...interface{})

	// Panicf logs a message at level Panic.
	Panicf(format string, args ...interface{})

	// Fatalf logs a message at level Fatal.
	Fatalf(format string, args ...interface{})

	// Debugln logs a message at level Debug.
	Debugln(args ...interface{})

	// Println logs a message at level Info.
	Println(args ...interface{})

	// Infoln logs a message at level Info.
	Infoln(args ...interface{})

	// Warnln logs a message at level Warn.
	Warnln(args ...interface{})

	// Warningln logs a message at level Warn.
	Warningln(args ...interface{})

	// Errorln logs a message at level Error.
	Errorln(args ...interface{})

	// Panicln logs a message at level Panic.
	Panicln(args ...interface{})

	// Fatalln logs a message at level Fatal.
	Fatalln(args ...interface{})
}
