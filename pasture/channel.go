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
			message = err.Error()
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
	done := make(chan struct{}, 4)
	go copyOut(och, rch, done)
	go copyOut(rch, och, done)
	go copyOut(och.Stderr(), rch.Stderr(), done)
	go copyOut(rch.Stderr(), och.Stderr(), done)

	/* Wait for a pipe to break */
	<-done
	fmt.Printf("\nDone.\n")
}

/* copyOut Copies src to dst and to stdout, and nonblockingly sends on done
when there's no more left to copy */
func copyOut(dst io.Writer, src io.Reader, done chan<- struct{}) {
	io.Copy(io.MultiWriter(os.Stdout, dst), src)
	select {
	case done <- struct{}{}:
	default:
	}
}
