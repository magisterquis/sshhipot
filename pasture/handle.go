package main

/*
 * handle.go
 * Handle incoming clients
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

/* handle handles an incoming client */
func handle(c net.Conn, conf *ssh.ServerConfig) {
	/* Log the connection, close it when we're done */
	log.Printf("%v Connect", c.RemoteAddr())
	defer log.Printf("%v Disconnect", c.RemoteAddr())

	/* Make into an SSH connection */
	cc, cchans, creqs, err := ssh.NewServerConn(c, conf)
	if nil != err {
		log.Printf("%v err: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}

	/* Dial the victim */
	vc, vchans, vreqs, elogmsg := dialVictim(cc.User())
	if "" != elogmsg {
		log.Printf("%v", elogmsg)
		cc.Close()
		return
	}
	defer vc.Close()
	/* Shut down the client connection when this one goes */
	go func(v, c ssh.Conn) {
		err := c.Wait()
		log.Printf("%v victim shut down: %v", ci(cc), err)
		v.Close()
	}(vc, cc)

	/* Logging info */
	info := ci(cc)

	/* Spawn handlers for channels and requests */
	go handleNewChannels(vchans, cc, info+" ChanDirection:Victim->Client")
	go handleNewChannels(cchans, vc, info+" ChanDirection:Client->Victim")
	go handleConnRequests(vreqs, cc, info+" ReqDirection:Victim->Client")
	go handleConnRequests(creqs, vc, info+" ReqDirection:Client->Victim")
	_ = vreqs
	_ = creqs

	/* Wait until the connection's shut down */
	err = cc.Wait()
	log.Printf("%v shut down: %v", ci(cc), err)
}
