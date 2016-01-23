package main

/*
 * request.go
 * Handles allowed requests
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

/* Sleep a bit before these requests to "avoid" race conditions.  Lousy, but
it should work.  Pull request, anybody? */
var delayedReqs = map[string]time.Duration{
	/* Workaround for requests getting there faster than channels */
	"no-more-sessions@openssh.com": 10 * time.Second,
	"shell": 3 * time.Second,
}

/* handleChannelRequests handles proxying requests read from reqs to the SSH
channel c.  info is used for logging. */
func handleChannelRequests(
	reqs <-chan *ssh.Request,
	c ssh.Channel,
	info string,
) {
	for r := range reqs {
		go handleRequest(
			r,
			func( /* Ugh, a closure */
				name string,
				wantReply bool,
				payload []byte,
			) (bool, []byte, error) {
				b, e := c.SendRequest(name, wantReply, payload)
				return b, nil, e
			},
			func() error { return c.Close() }, /* Another? */
			info,
		)
	}
}

/* handleConnRequests handles proxying requests read from reqs to the SSH
connection sc.  info is used for logging */
func handleConnRequests(
	reqs <-chan *ssh.Request,
	c ssh.Conn,
	info string,
) {
	for r := range reqs {
		go handleRequest(
			r,
			func(
				name string,
				wantReply bool,
				payload []byte,
			) (bool, []byte, error) {
				return c.SendRequest(name, wantReply, payload)
			},
			func() error { return c.Close() },
			info,
		)
	}
}

/* handleRequest handles proxying a request r via sr, which should be a closure
which sends the request passed to it on a channel or SSH connection.  If the
request can't be proxied, cl will be called to close whatever sr sends r on.
info is used for logging. */
func handleRequest(
	r *ssh.Request,
	sr func(
		name string,
		wantReply bool,
		payload []byte,
	) (bool, []byte, error),
	cl func() error,
	info string) {
	/* If this is the wrong sort of request, respond no */
	if s, ok := delayedReqs[r.Type]; ok {
		log.Printf(
			"%v Type:%v Delay:%v",
			info,
			r.Type,
			s,
		)
		time.Sleep(s)
	}
	logRequest(r, info)
	/* Ask the other side */
	ok, data, err := sr(r.Type, r.WantReply, r.Payload)
	if nil != err {
		log.Printf(
			"%v Unable to receive reply for %v request: %v",
			info,
			r.Type,
			err,
		)
		cl()
		return
	}
	logRequestResponse(r, ok, data, info)
	/* Proxy back */
	if err := r.Reply(ok, nil); nil != err {
		log.Printf(
			"%v Unable to reply to %v request: %v",
			info,
			r.Type,
			err,
		)
		cl()
	}
}

/* logRequest logs an incoming request */
func logRequest(r *ssh.Request, info string) {
	log.Printf(
		"%v Request Type:%q Payload:%q WantReply:%v",
		info,
		r.Type,
		r.Payload,
		r.WantReply,
	)
}

/* logRequestResponse logs the response for a request. */
func logRequestResponse(r *ssh.Request, ok bool, data []byte, info string) {
	log.Printf(
		"%v Response Type:%q Payload:%q OK:%v ResData:%q",
		info,
		r.Type,
		r.Payload,
		ok,
		data,
	)
}
