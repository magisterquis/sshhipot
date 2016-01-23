package main

/*
 * channel.go
 * Handle MitMing channels
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

/* handleNewChannels handles proxying channel requests read from chans to the
SSH connection sc.  info is used for logging. */
func handleNewChannels(
	chans <-chan ssh.NewChannel,
	sc ssh.Conn,
	info string,
) {
	for cr := range chans {
		go handleNewChannel(cr, sc, info)
	}
}

/* handleChannel proxies a channel request command or shell to the ssh
connection sc. */
func handleNewChannel(cr ssh.NewChannel, sc ssh.Conn, info string) {
	log.Printf(
		"%v Type:%q Data:%q NewChannel",
		info,
		cr.ChannelType(),
		cr.ExtraData(),
	)

	/* Make the same request to the other side */
	och, oreqs, err := sc.OpenChannel(cr.ChannelType(), cr.ExtraData())
	if nil != err {
		/* If we can't log it, and reject the client */
		oe, ok := err.(*ssh.OpenChannelError)
		var (
			reason  ssh.RejectionReason
			message string
		)
		if !ok {
			log.Printf(
				"%v Type:%q Data:%q Unable to open channel: "+
					"%v",
				info,
				cr.ChannelType(),
				cr.ExtraData(),
				err,
			)
			reason = ssh.ConnectionFailed
			message = "Fail"
		} else {
			log.Printf(
				"%v Type:%q Data:%q Reason:%q Message:%q "+
					"Unable to open channel",
				info,
				cr.ChannelType(),
				cr.ExtraData(),
				oe.Reason.String(),
				oe.Message,
			)
			reason = oe.Reason
			message = oe.Message
		}
		if err := cr.Reject(reason, message); nil != err {
			log.Printf(
				"%v Unable to pass on channel rejecton "+
					"request: %v",
				info,
				err,
			)
		}
		return
	}
	defer och.Close()

	/* Accept the channel request from the requestor */
	rch, rreqs, err := cr.Accept()
	if nil != err {
		log.Printf(
			"%v Unable to accept request for a channel of type "+
				"%q: %v",
			cr.ChannelType(),
			info,
			err,
		)
		return
	}
	defer rch.Close()

	/* Handle passing requests between channels */
	hcrinfo := fmt.Sprintf(" %v ChannelType:%q", info, cr.ChannelType())
	go handleChannelRequests(
		rreqs,
		och,
		hcrinfo+" ReqDir:AsDirection",
	)
	go handleChannelRequests(
		oreqs,
		rch,
		hcrinfo+" ReqDir:AgainstDirection",
	)

	log.Printf(
		"%v Type:%q Data:%q Opened",
		info,
		cr.ChannelType(),
		cr.ExtraData(),
	)

	/* For now, print out read data */
	go io.Copy(io.MultiWriter(os.Stdout, och), rch)
	go io.Copy(io.MultiWriter(os.Stdout, rch), och)
	go io.Copy(io.MultiWriter(os.Stdout, och.Stderr()), rch.Stderr())
	go io.Copy(io.MultiWriter(os.Stdout, rch.Stderr()), och.Stderr())

	/* TODO: Wait for it to close */
	time.Sleep(time.Minute) /* Well, this is horrible */
}
