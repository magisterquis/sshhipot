package main

/*
 * channel.go
 * Handle SSH channels
 * By J. Stuart McMurray
 * Created 20180410
 * Last Modified 20180513
 */

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// BUFLEN is the size of the channel read buffer
const BUFLEN = 1024

// HandleChannel handles a request for a channel.  If it's an interactive
// session, it's allowed and logged, otherwise it's silently proxied.
// If c accepts a channel to which to proxy the data sent on nc's channel,
// HandleChannel will return after the channel to c is created and nc is
// accepted and right after proxying begins.  Proxying will continue after
// HandleChannel returns.  If a shell is requested, it will be logged in ldir.
func HandleChannel(
	tag string,
	c ssh.Conn,
	nc ssh.NewChannel,
	ldir string,
	scr map[string]struct{},
	logMax uint,
) {
	/* Try to make the channel to the other side */
	pch, preqs, err := c.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if nil != err {
		if e, ok := err.(*ssh.OpenChannelError); ok {
			if err := nc.Reject(e.Reason, e.Message); nil != err {
				log.Printf(
					"[%v] Unable to reject %v channel: %v",
					tag,
					nc.ChannelType(),
					err,
				)
				return
			}
			log.Printf(
				"[%v] Proxy request for %v channel "+
					"rejected: %v (%v)",
				tag,
				nc.ChannelType(),
				e.Reason,
				e.Message,
			)
			return
		}
		log.Printf(
			"[%v] Unable to open %v channel: %v",
			tag,
			nc.ChannelType(),
			err,
		)
		return
	}
	/* pch: proxy channel */

	/* Accept channel request */
	ich, ireqs, err := nc.Accept()
	if nil != err {
		log.Printf(
			"[%v] Unable to accept %v channel: %v",
			tag,
			nc.ChannelType(),
			err,
		)
		pch.Close()
		return
	}
	/* ich: incomming channel */

	/* Log the channel */
	m := fmt.Sprintf("[%v] Channel %q", tag, nc.ChannelType())
	if 0 != len(nc.ExtraData()) {
		m += fmt.Sprintf(" (%q)", string(nc.ExtraData()))
	}
	log.Printf("%s", m)

	/* Start proxying between channels */
	go func() {

		/* Log file, in case we need it */
		lf := new(LogFile)
		lf = &LogFile{
			fname: filepath.Join(
				ldir,
				fmt.Sprintf(
					"%v-%v",
					tag,
					time.Now().Format(time.RFC3339),
				),
			),
			tag: tag,
			max: logMax,
		}

		/* Make sure both channels are closed when we return */
		defer pch.Close()
		defer ich.Close()
		dch := make(chan struct{}, 2)
		var once sync.Once
		done := func() { once.Do(func() { close(dch) }) }
		go proxyChannel(tag, lf, "i", pch, ich, ireqs, done, scr)
		go proxyChannel(tag, lf, "o", ich, pch, preqs, done, scr)
		<-dch

		log.Printf("[%v] Done.", tag)
	}()
}

/* proxyChannel proxies comms from s to d.  s's requests are on reqs.  The
direction of the channel ("i" or "o") is given in dir.  Done is called when
the channel's closed. */
func proxyChannel(
	tag string,
	lf *LogFile,
	dir string,
	d ssh.Channel,
	s ssh.Channel,
	reqs <-chan *ssh.Request,
	done func(),
	scr map[string]struct{},
) {
	/* Update the tag to use the direction as well */
	tag += dir
	itag := tag + "(i)"
	etag := tag + "(e)"

	/* Make sure done is called on exit if not before. */
	defer done()

	/* Make sure the logfile is closed on exit */
	defer lf.Close()

	/* Writers which include lf */
	iw := io.MultiWriter(lf.DirectionWriter(dir), d)
	ew := io.MultiWriter(lf.DirectionWriter(dir), d.Stderr())

	/* Convert streams to channels */
	ich := make(chan []byte) /* Input/Output */
	ech := make(chan []byte) /* Stderr */
	go readStream(tag+"(i)", ich, s)
	go readStream(tag+"(e)", ech, s.Stderr())
	defer drainStream(ich)
	defer drainStream(ech)

	/* Handle channels and reads */
	var nreq uint /* Request counter */
	for nil != reqs || nil != ich || nil != ech {
		/* Prioritize requests over reads */
		select {
		case req, ok := <-reqs: /* Channel request */
			requestCase(tag, d, &reqs, req, ok, &nreq, lf, scr)
		default:
			select {
			case req, ok := <-reqs:
				requestCase(
					tag,
					d,
					&reqs,
					req,
					ok,
					&nreq,
					lf,
					scr,
				)
			case b, ok := <-ich: /* Stdin/out */
				readCase(itag, iw, &ich, b, ok)
				if 0 != len(b) {
					log.Printf("[%v] %q", itag, string(b)) /* DEBUG */
				}
				/* If ich is nil now, we've no more to write */
				if nil != ich {
					break
				}
				if err := d.CloseWrite(); nil != err &&
					io.EOF != err {
					log.Printf(
						"[%v] Unable to close for "+
							"writing: %v",
						itag,
						err,
					)
				}
			case b, ok := <-ech: /* Stderr */
				readCase(etag, ew, &ech, b, ok)
				if 0 != len(b) {
					log.Printf("[%v] %q", etag, string(b)) /* DEBUG */
				}
			}
		}
	}
}

/* requestCase handles a received request (or channel close) from *ch, which
will be proxied to d.  ok is as returned from the channel receive, nreq is the
number of requests counter, lf is the LogFile for this channel. */
func requestCase(
	tag string,
	d ssh.Channel,
	ch *<-chan *ssh.Request,
	req *ssh.Request,
	ok bool,
	nreq *uint,
	lf *LogFile,
	silentChannelRequests map[string]struct{},
) {
	/* If the request channel was closed, don't try to receive again. */
	if !ok {
		*ch = nil
		return
	}

	/* Process the request.  If we can't process any more, drain the
	channel and don't try to read any more. */
	if done := handleChannelRequest(
		tag,
		lf,
		d,
		req,
		nreq,
		silentChannelRequests,
	); done {
		go ssh.DiscardRequests(*ch)
		*ch = nil
	}
}

/* readCase handles a receive (or channel close) from *ch, which will be
proxied to w. ok is as returned from the channel receive.  cw will be called if
it is not till and ok is false. */
func readCase(tag string, w io.Writer, ch *chan []byte, b []byte, ok bool) {
	/* If the channel was closed, don't try to receive again. */
	if !ok {
		*ch = nil
		return
	}

	/* Try to write to the other side */
	if _, err := w.Write(b); nil != err {
		log.Printf("[%v] Write error: %v", tag, err)
		*ch = nil
	}
	/* TODO: Handle logging (should be a multiwriter) */
}

/* handleChannelRequest handles a single request on the channel.  The
arguments aside from req are the same as for proxyChannel.  Nreq is a unique
number for this request.  True is returned if the we're done sending requests.
*/
func handleChannelRequest(
	tag string,
	lf *LogFile,
	d ssh.Channel,
	req *ssh.Request,
	nreq *uint,
	silentChannelRequests map[string]struct{},
) (done bool) {
	/* Tag for this request */
	rtag := fmt.Sprintf("%v-r%v", tag, *nreq)
	*nreq++
	LogRequest(rtag, req, false, silentChannelRequests)

	switch req.Type {
	case "eow@openssh.com": /* As good as an EOF */
		if err := d.CloseWrite(); nil != err && io.EOF != err {
			log.Printf(
				"[%v] Unable to close for writing on eow: %v",
				tag,
				err,
			)
		}
	case "pty-req": /* Gives us window size */
		if err := lf.ParsePTYPayload(req.Payload); nil != err {
			log.Printf(
				"[%v] Unable to parse pty-req payload: %v",
				tag,
				err,
			)
			break
		}
		log.Printf("[%v] Terminal %s", rtag, lf.PTYString())
	case "shell": /* Start a shell */
		if err := lf.Start(""); nil != err {
			log.Printf(
				"[%v] Unable to start shell logging: %v",
				tag,
				err,
			)
			break
		}
	case "exec": /* Run a command */
		if err := lf.Start(string(req.Payload)); nil != err {
			log.Printf(
				"[%v] Unable to start exec logging: %v",
				tag,
				err,
			)
		}
	}
	/* Proxy the request to the other side. */
	if err := ProxyRequest(
		ChannelRequestReceiver{d},
		req,
	); nil != err {
		log.Printf(
			"[%v] Unable to proxy %v request: %v",
			rtag,
			req.Type,
			err,
		)
		done = true
	}
	return
}

/* readStream reads from r and sends read slices to ch.  It closes ch when
a read from r returns an error. */
func readStream(tag string, ch chan<- []byte, r io.Reader) {
	var (
		n   int
		err error
	)
	/* Close the channel when we're done with it */
	defer close(ch)
	for {
		/* Read buffer.  Loop scope so we don't change what's sent
		on the channel if it takes a while to be used. */
		b := make([]byte, BUFLEN)
		/* Read from the reader, send what's read to the channel */
		n, err = r.Read(b)
		/* Handle any bytes read before any errors */
		if 0 != n {
			ch <- b[:n]
		}
		/* EOFs just mean we're done */
		if io.EOF == err {
			return
		}
		if nil != err {
			log.Printf("[%v] Stream read error: %v", tag, err)
			return
		}
	}
}

/* drainStream reads from ch until it is closed.  The read values are then
discarded. */
func drainStream(ch <-chan []byte) {
	for range ch {
	}
}
