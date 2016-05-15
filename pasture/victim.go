package main

/*
 * victim.go
 * Create a connection to the victim
 * By J. Stuart McMurray
 * Created 20150122
 * Last Modified 20150122
 */

import (
	"flag"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

var (
	vicAddr = flag.String(
		"c",
		"192.168.11.7:222",
		"Real SSH server's `address`",
	)
	vicUser = flag.String(
		"u",
		"",
		"If set, connect to the real SSH server with this `username` "+
			"regardless of what the client sent",
	)
	vicPass = flag.String(
		"p",
		"iscaitlinjoiningus",
		"Authenticate to the real SSH server with this `password`",
	)
)

/* dialVictim dials the victim with the supplied username, which may have been
overridden on the command line. */
func dialVictim(user string) (
	ssh.Conn,
	<-chan ssh.NewChannel,
	<-chan *ssh.Request,
	string,
) {
	/* Username to use on the remote end */
	u := *vicUser
	if "" == u {
		u = user
	}
	/* Try to make a connection to the victim */
	nc, err := net.Dial("tcp", *vicAddr)
	if nil != err {
		return nil, nil, nil, fmt.Sprintf(
			"Unable to connect to victim %v: %v",
			*vicAddr,
			err,
		)
	}

	c, reqs, chans, err := ssh.NewClientConn(nc, *vicAddr, &ssh.ClientConfig{
		User: u,
		Auth: []ssh.AuthMethod{ssh.Password(*vicPass)},
	})
	if nil != err {
		return c, reqs, chans, fmt.Sprintf(
			"Unable to SSH to victim as %v@%v / %v: %v",
			u,
			*vicAddr,
			*vicPass,
			err,
		)
	}
	return c, reqs, chans, ""
}
