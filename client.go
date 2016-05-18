package main

/*
 * client.go
 * SSH client to connect upstream
 * By J. Stuart McMurray
 * Created 20160515
 * Last Modified 20160517
 */

import (
	"bytes"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

const TIMEOUT = time.Minute

/* clientDial dials the real server and makes an SSH client */
func clientDial(
	addr string,
	conf *ssh.ClientConfig,
) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	/* Connect to the server */
	c, err := net.Dial("tcp", addr)
	if nil != err {
		return nil, nil, nil, err
	}
	return ssh.NewClientConn(c, addr, conf)
	//sc,chans,reqs,err :=
	//func NewClientConn(c net.Conn, addr string, config *ClientConfig)
	///* Connect to server */
	//c, err := ssh.Dial("tcp", addr, conf)
	//if nil != err {
	//	return nil, err
	//}
	//return c, nil
}

/* clientConfig makes an SSH client config which uses the given username and
key */
func makeClientConfig(user, key string) *ssh.ClientConfig {
	/* Get SSH key */
	k, g, err := getKey(key)
	if nil != err {
		log.Fatalf("Unable to get client key: %v", err)
	}
	if g {
		log.Printf("Generated client key in %v", key)
		log.Printf(
			"Public Key: %s",
			bytes.TrimSpace(ssh.MarshalAuthorizedKey(k.PublicKey())),
		)
	} else {
		log.Printf("Loaded client key from %v", key)
	}
	/* Config to return */
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(k),
		},
		Timeout: TIMEOUT,
	}
}
