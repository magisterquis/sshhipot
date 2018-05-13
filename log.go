package main

/*
 * log.go
 * Set up logging
 * By J. Stuart McMurray
 * Created 20180513
 * Last Modified 20180513
 */

import (
	"io"
	"log"
	"log/syslog"
	"os"
)

/* logWriter turns a *log.Logger into an io.Writer */
type logWriter struct{ *log.Logger }

/* Write turns the log.Logger into an io.Writer */
func (l logWriter) Write(b []byte) (int, error) {
	return len(b), l.Output(2, string(b))
}

// SetLogging works out logging output.  If fn is not the empty string, logs
// will be appended to a file with the given name.  If useSyslog is true, logs
// will also be sent to syslog. */
func SetLogging(fn string, useSyslog bool) {
	/* File output and stdout both need timestamps */
	o := []io.Writer{os.Stdout}
	if "" != fn {
		/* Open or create logfile */
		f, err := os.OpenFile(
			fn,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY,
			0600,
		)
		if nil != err {
			log.Fatalf("Unable to open logfile %q: %v", fn, err)
		}
		/* f will be closed on exit */
		o = append(o, f)
	}
	log.SetOutput(io.MultiWriter(o...))

	/* If we're not using syslog, this is sufficient */
	if !useSyslog {
		return
	}

	/* Logger which adds timestamps */
	tsl := log.New(io.MultiWriter(o...), "", log.LstdFlags)

	/* If we're also using syslog, we'll need a new logger which will
	not add timestamps, plus a timestamp-adding logger for stdout/file. */
	l, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "")
	if nil != err {
		log.Fatalf("Unable to log to syslog: %v", err)
	}

	/* Make the default logger not add timestamps, and set it to log to
	syslog and the timestamping logger */
	log.SetFlags(0)
	log.SetOutput(io.MultiWriter(logWriter{tsl}, l))

}
