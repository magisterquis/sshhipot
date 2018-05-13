package main

/*
 * request.go
 * Handles global and channel requests
 * By J. Stuart McMurray
 * Created 20180410
 * Last Modified 20180512
 */

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

// RequestReceiver is any type which can receive an SSH request.  It is
// satisfied by at least ssh.Conn and ssh.Channel.
type requestReceiver interface {
	SendRequest(
		name string,
		wantReply bool,
		payload []byte,
	) (bool, []byte, error)
}

// ChannelRequestReceiver wraps an ssh.Channel and turns it into a
// RequestReceiver.
type ChannelRequestReceiver struct {
	ch ssh.Channel
}

// SendRequest wraps crr.ch's SendRequest and always returns a nil byte
// slice.
func (crr ChannelRequestReceiver) SendRequest(
	name string,
	wantReply bool,
	payload []byte,
) (bool, []byte, error) {
	ok, err := crr.ch.SendRequest(name, wantReply, payload)
	return ok, nil, err
}

// ProxyRequest proxies r to rr.
func ProxyRequest(
	rr requestReceiver,
	r *ssh.Request,
) error {
	/* Proxy request upstream */
	ok, b, err := rr.SendRequest(r.Type, r.WantReply, r.Payload)
	if nil != err {
		return err
	}
	/* Done if there's no need for a reply */
	if !r.WantReply {
		return nil
	}

	/* Send it back if there's a reply */
	if err := r.Reply(ok, b); nil != err {
		return err
	}
	return nil
}

// LogRequest logs the request.  If global is true, it is logged as a global
// request.  The request will not be logged if its type is in m.
func LogRequest(
	tag string,
	req *ssh.Request,
	global bool,
	m map[string]struct{},
) {
	/* Don't log it if it's in m */
	if _, ok := m[req.Type]; ok {
		return
	}

	msg := fmt.Sprintf("[%v] ", tag)
	if global {
		msg += "Global request "
	} else {
		msg += "Request "
	}
	msg += fmt.Sprintf("%s WantReply:%v", req.Type, req.WantReply)
	if 0 != len(req.Payload) {
		msg += fmt.Sprintf(" %q", string(req.Payload))
	}
	log.Printf("%s", msg)
}
