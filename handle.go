package main

/*
 * handle.go
 * Handle incoming connections
 * By J. Stuart McMurray
 * Created 20180407
 * Last Modified 20180512
 */

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Handle proxies the connection from c (which will be upgraded to SSH) to the
// upstream server upstream.  The SSH connection to c will use skey for the
// host key and version for the version banner.  The connection to the upstream
// server will use ckey to authenticate the client as the given user and hkey
// to authenticate the server.  If a channel is made on which a shell is
// requested, it will be logged in ldir.
func Handle(
	c net.Conn,
	ckey ssh.Signer,
	skey ssh.Signer,
	hkey ssh.PublicKey,
	user string,
	version string,
	upstream string,
	timeout time.Duration,
	done func(),
	ldir string,
	silentGlobalRequests map[string]struct{},
	silentChannelRequests map[string]struct{},
	banner string,
	creds map[string]map[string]struct{},
	logMax uint,
) {
	defer done()
	defer c.Close()

	/* Log tag */
	tag := c.RemoteAddr().String()

	/* Make server config */
	sconf := MakeServerConfig(tag, skey, version, banner, creds)

	/* SSH handshake with the client */
	dch, to := startTimeout(timeout, func() { c.Close() })
	cc, cchans, creqs, err := ssh.NewServerConn(c, sconf)
	close(dch)
	if *to {
		log.Printf("[%v] Client handshake timeout", tag)
		return
	} else if nil != err {
		log.Printf("[%v] Client handshake error: %v", tag, err)
		return
	}
	defer cc.Close()

	/* Connect to upstream server */
	unc, err := net.DialTimeout("tcp", upstream, timeout)
	if nil != err {
		log.Printf(
			"[%v] Server connection error: %v",
			tag,
			err,
		)
		return
	}
	defer unc.Close()

	/* Handshake as client */
	dch, to = startTimeout(timeout, func() { unc.Close() })
	uc, uchans, ureqs, err := ssh.NewClientConn(
		unc,
		unc.RemoteAddr().String(),
		MakeClientConfig(
			user,
			string(cc.ClientVersion()),
			ckey,
			hkey,
		),
	)
	close(dch)
	if *to {
		log.Printf("[%v] Server handshake timeout", tag)
		return
	} else if nil != err {
		log.Printf("[%v] Server handshake error: %v", tag, err)
		return
	}
	defer uc.Close()

	/* Channels for notification one side or the other has closed the
	connection */
	cdone := make(chan error, 1)
	go func() { cdone <- cc.Wait() }()
	udone := make(chan error, 1)
	go func() { udone <- uc.Wait() }()

	/* Proxy channels, requests, and closes */
	var (
		/* Counters for requests and channels */
		ncreq int
		nureq int
		ncnc  int
		nunc  int

		cl string /* Who closed the connection */
	)

HANDLELOOP:
	for {
		select {
		/* These two channels are duplicated in the default case
		to prioritize them */
		case nc, ok := <-cchans: /* Channel request from client */
			newChannelCase(
				tag,
				"f",
				&ncnc,
				uc,
				nc,
				ok,
				&cchans,
				ldir,
				silentChannelRequests,
				logMax,
			)
		case nc, ok := <-uchans: /* Channel request from upstream server */
			newChannelCase(
				tag,
				"b",
				&nunc,
				cc,
				nc,
				ok,
				&uchans,
				ldir,
				silentChannelRequests,
				logMax,
			)
		default:
			select {
			case nc, ok := <-cchans: /* Channel request from client */
				newChannelCase(
					tag,
					"f",
					&ncnc,
					uc,
					nc,
					ok,
					&cchans,
					ldir,
					silentChannelRequests,
					logMax,
				)
			case nc, ok := <-uchans: /* Channel request from upstream server */
				newChannelCase(
					tag,
					"r",
					&nunc,
					cc,
					nc,
					ok,
					&uchans,
					ldir,
					silentChannelRequests,
					logMax,
				)
			case req, ok := <-creqs: /* Global request from client */
				if !ok {
					creqs = nil
					continue
				}
				t := fmt.Sprintf("%vf-r%v", tag, ncreq)
				ncreq++
				if err := ProxyRequest(uc, req); nil != err {
					log.Printf(
						"[%v] Unable to proxy global "+
							"%v request: %v",
						t,
						req.Type,
						err,
					)
					break
				}
				LogRequest(t, req, true, silentGlobalRequests)
			case req, ok := <-ureqs: /* Global request from upstream server */
				if !ok {
					ureqs = nil
					continue
				}
				t := fmt.Sprintf("%vb-r%v", tag, nureq)
				nureq++
				if err := ProxyRequest(cc, req); nil != err {
					log.Printf(
						"[%v] Unable to proxy global "+
							"%v request: %v",
						t,
						req.Type,
						err,
					)
					break
				}
				LogRequest(t, req, true, silentGlobalRequests)
			case err = <-cdone: /* Client connection closed */
				cl = "client"
				break HANDLELOOP
			case err = <-udone: /* Upstream server connection closed */
				cl = "client"
				break HANDLELOOP
			}
		}
	}

	/* Log connection close */
	var estr string
	if nil != err {
		estr = fmt.Sprintf(": %v", err)
	}
	log.Printf("[%v] Finished, %v exit%v", tag, cl, estr)
}

/* startTimeout calls cancel if the returned channel isn't closed before
timeout elapses.  If timeout elapses before the returned channel is closed,
the boolean pointer will point to a true value. */
func startTimeout(
	timeout time.Duration,
	cancel func(),
) (chan<- struct{}, *bool) {
	done := make(chan struct{}) /* Indicates work was finished */
	var to bool                 /* True on timeout */

	/* Wait for either work done or a timeout */
	go func() {
		select {
		case <-time.After(timeout): /* Timeout */
			cancel()
			to = true
		case <-done: /* Work finished */
		}
	}()

	return done, &to
}

/* newChannelCase handles the case in a select statement in which a new channel
to be proxied has been requested.  nc is the new channel, which was received on
ch.  If ok is false, ch is assumed closed and will be replaced with nil.  nc
will be proxied to a channel on c.  nnc is the nc counter and dir is the
direction.  If a shell is requested it will be logged in ldir. */
func newChannelCase(
	tag string,
	dir string,
	nnc *int,
	c ssh.Conn,
	nc ssh.NewChannel,
	ok bool,
	ch *<-chan ssh.NewChannel,
	ldir string,
	silentChannelRequests map[string]struct{},
	logMax uint,
) {
	if !ok {
		*ch = nil
		return
	}
	HandleChannel(
		fmt.Sprintf("%v%v-c%v", tag, dir, *nnc),
		c,
		nc,
		ldir,
		silentChannelRequests,
		logMax,
	)
	*nnc++
}
