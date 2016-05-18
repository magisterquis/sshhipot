package main

/*
 * request.go
 * Handle ssh requests
 * By J. Stuart McMurray
 * Created 20160517
 * Last Modified 20160518
 */

import (
	"crypto/subtle"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

/* Requestable is anything with a SendRequest */
type Requestable interface {
	SendRequest(
		name string,
		wantReply bool,
		payload []byte,
	) (bool, []byte, error)
}

/* handleReqs logs each received request and proxies it to the server. */
/* handleReqs handles the requests which come in on reqs and proxies them to
rable.  All of this is logged to lg, prefixed with desc, which should
indicate the direction (e.g. attacker->server) of the request. */
func handleReqs(
	reqs <-chan *ssh.Request,
	rable Requestable,
	lg *log.Logger,
	direction string,
) {
	/* Read requests until there's no more */
	for r := range reqs {
		handleRequest(r, rable, lg, direction)
	}
}

/* handleRequest handles a single request, which is proxied to rable and logged
via lg. */
func handleRequest(
	r *ssh.Request,
	rable Requestable,
	lg *log.Logger,
	direction string,
) {
	rl := fmt.Sprintf(
		"Type:%q WantReply:%v Payload:%q Direction:%q",
		r.Type,
		r.WantReply,
		r.Payload,
		direction,
	)
	/* Ignore no-more-sessions methods, because we're bad people */
	if IGNORENMS {
		if 1 == subtle.ConstantTimeCompare(
			[]byte(r.Type),
			[]byte("no-more-sessions@openssh.com"),
		) {
			lg.Printf("Ignoring Request %s", rl)
			return
		}
	}
	/* Proxy to server */
	ok, data, err := rable.SendRequest(r.Type, r.WantReply, r.Payload)
	if nil != err {
		lg.Printf("Unable to proxy request %s Error:%v", rl, err)
		return
	}

	/* TODO: Pass to server */
	if err := r.Reply(ok, data); nil != err {
		lg.Printf("Unable to respond to request %s Error:%v", rl, err)
		return
	}

	lg.Printf("Request %s Ok:%v Response:%q", rl, ok, data)
}
