package main

/*
 * cast.go
 * Logging for shell sessions
 * By J. Stuart McMurray
 * Created 20180422
 * Last Modified 20180513
 */

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// LDIRPERMS are the permissions with which to make the log directory
	LDIRPERMS = 0700

	// LOGSUFFIX is the suffix (extension) to append to log files
	LOGSUFFIX = "cast"
)

/* asciicastHeader is the first line of an asciicast file.  It contains
metadata needed for playback. */
type asciicastHeader struct {
	Version   int                   `json:"version"`
	Width     uint32                `json:"width"`
	Height    uint32                `json:"height"`
	Timestamp int64                 `json:"timestamp"`
	Env       struct{ TERM string } `json:"env"`
	Command   string                `json:"command,omitempty"`
}

// LogFile logs shell i/o to an asciicast file.  If Init is called before
// the first write, a header with the data passed to Init will be written.
// Otherwise on first use a default header will be written.  The logfile won't
// be opened until the first write.
type LogFile struct {
	sync.Mutex
	tag string

	/* Control of the maximum log size */
	max uint /* Maximum size, in bytes */
	nw  uint /* Number of bytes written */

	/* Logfile */
	fname  string
	f      *os.File
	done   bool /* Failed to open file */
	header bool /* True after we've written the header */

	/* Sent in a request, describes the terminal */
	term   string
	width  uint32
	height uint32

	/* Command which is run, if not a shell */
	command string

	/* Shell start */
	start time.Time
}

// DirectionWriter returns an io.Writer which writes events to the asciicast
// with the given direction, which must be either "i" or "o".
func (l *LogFile) DirectionWriter(dir string) io.Writer {
	/* Make sure we have an acceptible direction */
	if "o" != dir && "i" != dir {
		log.Panicf("invalid direction %q", dir)
	}
	return logFileWriter{l, dir}
}

// WriteShell writes b to l as asciicast v2 JSON.  The direction is set by d,
// which should be either i or o.  Times will be calculated as offsets from
// l.start.  If l.f is nil, writeShell attempts to open it.  If the logfile
// was unable to be opened, writeShell is a no-op and returns the length of b
// (notionally written to a non-existent logfile?).
func (l *LogFile) WriteShell(b []byte, d string) (int, error) {
	l.Lock()
	defer l.Unlock()

	/* Don't bother if we can't logfile */
	if l.done {
		return len(b), nil
	}

	/* Don't bother if we haven't started */
	if l.start.IsZero() {
		return len(b), nil
	}

	/* Open logfile if we haven't one */
	if nil == l.f {
		/* Make sure we have a filename */
		if "" == l.fname {
			panic("no log filename")
		}

		var err error
		/* Make sure we have a directory */
		if err := os.MkdirAll(
			filepath.Dir(l.fname),
			LDIRPERMS,
		); nil != err {
			l.done = true
			return 0, err
		}
		/* Make the file */
		l.f, err = os.Create(l.fname)
		if nil != err {
			l.done = true
			return 0, err
		}
		log.Printf("[%v] Will log to %v", l.tag, l.fname)
	}

	/* Write the header if we've not already */
	if !l.header {
		if err := l.WriteHeader(); nil != err {
			l.done = true
			l.f.Close()
			return 0, err
		}
	}

	/* Make sure the direction is valid */
	if "i" != d && "o" != d {
		log.Panicf("bad direction %v", d)
	}

	/* Event to log, JSONified */
	a := [3]interface{}{
		time.Since(l.start).Seconds(), /* Timestamp */
		d,         /* Direction */
		string(b), /* Payload */
	}
	j, err := json.Marshal(a)
	if nil != err {
		return 0, err
	}

	/* Don't write if the file's too big */
	if uint(len(j)) > l.max-l.nw {
		l.done = true
		l.f.Close()
		return len(b), nil
	}

	/* Write to file */
	if _, err := fmt.Fprintf(l.f, "%s\n", string(j)); nil != err {
		l.done = true
		l.f.Close()
		return 0, err
	}

	return len(b), nil
}

// Close closes the file in l
func (l *LogFile) Close() error {
	l.Lock()
	defer l.Unlock()

	/* Don't bother if we're done already */
	if l.done {
		return nil
	}

	/* Close file */
	l.done = true
	return l.f.Close()
}

// WriteHeader writes an asciicast v2 header to the l.f.
func (l *LogFile) WriteHeader() error {
	/* Roll and write the header */
	hdr := asciicastHeader{
		Version:   2,
		Height:    l.height,
		Width:     l.width,
		Timestamp: l.start.Unix(),
		Command:   l.command,
	}
	hdr.Env.TERM = l.term
	b, err := json.Marshal(hdr)
	if nil != err {
		l.done = true
		l.f.Close()
		return err
	}
	if _, err := fmt.Fprintf(l.f, "%s\n", string(b)); nil != err {
		l.done = true
		l.f.Close()
		return err
	}
	l.header = true

	return nil
}

// ParsePTYPayload parses the payload of a PTY request to extract the terminal
// type (i.e. TERM variable) and terminal size.
func (l *LogFile) ParsePTYPayload(r []byte) error {
	l.Lock()
	defer l.Unlock()

	/* If we already have PTY, return an error */
	if "" != l.term {
		return errors.New("pty already set")
	}

	/* Pop the TERM variable size */
	if 4 > len(r) {
		return errors.New("too short for TERM length")
	}
	tlen := binary.BigEndian.Uint32(r[:4])
	r = r[4:]

	/* Pop the variable */
	if int(tlen) > len(r) {
		return errors.New("too short for TERM variable")
	}
	l.term = string(r[:tlen])
	r = r[tlen:]

	/* Pop the width and height */
	if 0 > len(r) {
		return errors.New("too short for terminal size")
	}
	l.width = binary.BigEndian.Uint32(r[:4])
	l.height = binary.BigEndian.Uint32(r[4:8])

	return nil
	/* TODO: Handle window change */
}

// PTYString returns the PTY values as a string.
func (l *LogFile) PTYString() string {
	l.Lock()
	defer l.Unlock()

	/* Should never happen */
	if "" == l.term {
		panic("pty unset")
	}

	return fmt.Sprintf("%q %vx%v", l.term, l.width, l.height)
}

// Start indicates l can start logging events.  The command logged in the
// asciicast may be set.
func (l *LogFile) Start(command string) error {
	l.Lock()
	defer l.Unlock()

	/* Don't start if we're done */
	if l.done {
		return errors.New("start after finish")
	}

	/* Don't start twice */
	if !l.start.IsZero() {
		return errors.New("already started")
	}

	l.command = command
	l.start = time.Now()
	return nil
}

/* logFileWriter is an io.Writer which logs to l using the specified direction,
which must be "i" or "o" */
type logFileWriter struct {
	l *LogFile
	d string
}

/* Write writes to l.l.WriteShell with the given direction. */
func (l logFileWriter) Write(b []byte) (int, error) {
	if "i" != l.d && "o" != l.d {
		log.Panicf("bad direction %q", l.d)
	}
	return l.l.WriteShell(b, l.d)
}
