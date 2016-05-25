package main

/*
 * channel.go
 * Handle channel opens
 * By J. Stuart McMurray
 * Created 20160517
 * Last Modified 20160518
 */

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

const BUFLEN = 1024

/* Channel wraps an ssh.Channel so we can have a consistent SendRequest */
type Channel struct {
	oc ssh.Channel
}

/* SendRequest emulates ssh.Conn's SendRequest */
func (c Channel) SendRequest(
	name string,
	wantReply bool,
	payload []byte,
) (bool, []byte, error) {
	ok, err := c.oc.SendRequest(name, wantReply, payload)
	return ok, []byte{}, err
}

/* handleChans logs each channel request, which will be proxied to the
client. */
func handleChans(
	chans <-chan ssh.NewChannel,
	client ssh.Conn,
	ldir string,
	lg *log.Logger,
	direction string,
) {
	/* Read channel requests until there's no more */
	for cr := range chans {
		go handleChan(cr, client, ldir, lg, direction)
	}
}

/* handleChan handles a single channel request from sc, proxying it to the
client.  General logging messages will be written to lg, and channel-specific
data and messages will be written to a new file in ldir. */
func handleChan(
	nc ssh.NewChannel,
	client ssh.Conn,
	ldir string,
	lg *log.Logger,
	direction string,
) {
	/* Log the channel request */
	crl := fmt.Sprintf(
		"Type:%q Data:%q Direction:%q",
		nc.ChannelType(),
		nc.ExtraData(),
		direction,
	)

	/* Pass to server */
	cc, creqs, err := client.OpenChannel(
		nc.ChannelType(),
		nc.ExtraData(),
	)
	if nil != err {
		go rejectChannel(err, crl, nc, lg)
		return
	}

	defer cc.Close()

	/* Make channel to attacker, defer close */
	ac, areqs, err := nc.Accept()
	if nil != err {
		lg.Printf(
			"Unable to accept channel request of type %q: %v",
			nc.ChannelType(),
			err,
		)
		return
	}
	defer ac.Close()

	/* Channel worked, make a logger for it */
	clg, lf, clgn, err := logChannel(ldir, nc)
	if nil != err {
		lg.Printf(
			"Unable to open log file for channel of type %q:%v",
			nc.ChannelType(),
			err,
		)
		return
	}
	defer lf.Close()
	clg.Printf("Start of log")

	/* Proxy requests on channels */
	go handleReqs(areqs, Channel{oc: cc}, clg, "attacker->server")
	go handleReqs(creqs, Channel{oc: ac}, clg, "server->attacker")

	/* Log the channel */
	lg.Printf("Channel %s Log:%q", crl, clgn)

	/* Proxy comms */
	wg := make(chan int, 4)
	go ProxyChannel(
		ac,
		cc,
		clg,
		"server->attacker",
		wg,
		1,
	)
	go ProxyChannel(
		cc,
		ac,
		clg,
		"attacker->server",
		wg,
		1,
	)
	go ProxyChannel(
		cc.Stderr(),
		ac.Stderr(),
		clg,
		"attacker-(err)->server",
		wg,
		0,
	)
	go ProxyChannel(
		ac.Stderr(),
		cc.Stderr(),
		clg,
		"server-(err)->attacker",
		wg,
		0,
	)
	sum := 0
	for i := range wg {
		sum += i
		if 2 <= sum {
			break
		}
	}

	/* TODO: Proxy comms */
}

/* logChannel returns a logger which can be used to log channel activities to a
file in the directory ldir.  The logger as well as the filename are
returned. */
func logChannel(
	ldir string,
	nc ssh.NewChannel,
) (*log.Logger, *os.File, string, error) {
	/* Log file is named after the channel time and type */
	logName := filepath.Join(
		ldir,
		time.Now().Format(LOGFORMAT)+"-"+nc.ChannelType(),
	)
	/* Open the file */
	lf, err := os.OpenFile(
		logName,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if nil != err {
		return nil, nil, "", err
	}
	return log.New(
		//lf,
		io.MultiWriter(lf, os.Stderr), /* DEBUG */
		"",
		log.LstdFlags|log.Lmicroseconds,
	), lf, logName, nil
}

/* rejectChannel tells the attacker the channel's been rejected by the real
server.  It requires the error from the channel request to the real server, the
channel request log string, the channel request from the attacker, and the
logger for the connection. */
func rejectChannel(nce error, crl string, nc ssh.NewChannel, lg *log.Logger) {
	/* Values to return to the attacker */
	reason := ssh.Prohibited
	message := nce.Error()
	/* Try and get the real story */
	if oce, ok := nce.(*ssh.OpenChannelError); ok {
		reason = oce.Reason
		message = oce.Message
	}
	lg.Printf(
		"Channel Rejection %v Reason:%v Message:%q",
		crl,
		reason,
		message,
	)
	/* Send the rejection */
	if err := nc.Reject(reason, message); nil != err {
		lg.Printf(
			"Unable to respond to channel request of type %q: %v",
			nc.ChannelType(),
			err,
		)
	}
}

/* ProxyChannel copies data from one channel to another */
func ProxyChannel(
	w io.Writer,
	r io.Reader,
	lg *log.Logger,
	tag string,
	wg chan<- int,
	token int,
) {
	defer func(c chan<- int, i int) { c <- i }(wg, token)
	var (
		buf  = make([]byte, BUFLEN)
		done = false
		n    int
		err  error
	)
	var lines [][]byte
	for !done {
		/* Reset buffer */
		buf = buf[:cap(buf)]
		/* Read a bit */
		n, err = r.Read(buf)
		buf = buf[:n]
		if nil != err {
			lg.Printf("[%v] Read Error: %v", tag, err)
			done = true
		}
		/* Don't bother if we didn't get anything */
		if 0 == n {
			continue
		}
		/* Send it on */
		if _, err = w.Write(buf); nil != err {
			lg.Printf("[%v] Write Error: %v", tag, err)
			done = true
		}
		if done {
			continue
		}
		/* Log it all */
		lines = bytes.SplitAfter(buf, []byte{'\n'})
		for i := range lines {
			lg.Printf("[%v] %q", tag, lines[i])
		}
	}
	lg.Printf("[%v] Finished", tag)
}
