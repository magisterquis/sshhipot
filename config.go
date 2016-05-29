package main

/*
 * config.go
 * Make a server config
 * By J. Stuart McMurray
 * Created 20160514
 * Last Modified 20160517
 */

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"

	"golang.org/x/crypto/ssh"
)

/* Baked in config.  Ugly :( */
const (
	// IGNORENMS causes no-more-sessions messages to not be relayed.  This
	// is a dirty hack to avoid a race condition in which the
	// no-more-sessions message gets there before the session request.  :(
	IGNORENMS = true
)

func makeServerConfig(
	noAuthNeeded bool,
	serverVersion string,
	password, passList string,
	passProb float64,
	hostname string,
	keyname string,
) *ssh.ServerConfig {
	/* Get allowed passwords */
	passwords, err := getPasswords(password, passList)
	if nil != err {
		log.Fatalf("Unable to get allowed passwords: %v", err)
	}
	/* Make sure we have a password */
	if 0 == len(passwords) {
		if !noAuthNeeded {
			log.Fatalf("no passwords from command line or " +
				"password file and authless connections " +
				"not allowed",
			)
		}
	} else {
		log.Printf("Will accept %v passwords", len(passwords))
	}
	/* Get server key */
	key, gen, err := getKey(keyname)
	if nil != err {
		log.Fatalf("Error generating/loading key: %v", err)
	}
	if gen {
		log.Printf("Generated key and stored in %v", keyname)
	} else {
		log.Printf("Loaded key from %v", keyname)
	}
	/* Config to return */
	c := &ssh.ServerConfig{
		NoClientAuth:     noAuthNeeded,
		ServerVersion:    serverVersion,
		PasswordCallback: passwordCallback(passwords, passProb),
		KeyboardInteractiveCallback: keyboardInteractiveCallback(
			passwords,
			hostname,
			passProb,
		),
		PublicKeyCallback: publicKeyCallback(),
	}
	c.AddHostKey(key)

	return c
}

/* passwordCallback makes a callback function which accepts the allowed
passwords */
func passwordCallback(
	passwords map[string]struct{},
	passProb float64,
) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	/* Return a function to check for the password */
	return func(
		conn ssh.ConnMetadata,
		password []byte,
	) (*ssh.Permissions, error) {
		p := string(password)
		_, ok := passwords[p]
		if !ok && diceRoll(passProb) {
			ok = true
		}
		logAttempt(conn, "Password", p, ok)
		if ok {
			return nil, nil
		}
		return nil, fmt.Errorf("Permission denied, please try again.")
	}
}

/* getPasswords gets the set of allowed passwords */
func getPasswords(password, passList string) (map[string]struct{}, error) {
	/* List of allowable passwords */
	ps := make(map[string]struct{})

	/* Password on command line */
	if "" != password {
		ps[password] = struct{}{}
	}

	/* Also, the lines of the file */
	if "" != passList {
		pbytes, err := ioutil.ReadFile(passList)
		if nil != err {
			return nil, err
		}
		/* Remove a single trailing \n */
		if '\n' == pbytes[len(pbytes)-1] {
			pbytes = pbytes[0 : len(pbytes)-1]
		}
		/* Make sure there's something */
		if 0 == len(pbytes) {
			return ps, nil
		}
		lines := bytes.Split(pbytes, []byte("\n"))
		for _, line := range lines {
			ps[string(line)] = struct{}{}
		}
	}

	return ps, nil
}

/* keyboardInteractiveCallback returns a keyboard-interactive callback which
accepts any of the allowed passwords. */
func keyboardInteractiveCallback(
	passwords map[string]struct{},
	hostname string,
	passProb float64,
) func(
	ssh.ConnMetadata,
	ssh.KeyboardInteractiveChallenge,
) (*ssh.Permissions, error) {
	return func(
		conn ssh.ConnMetadata,
		client ssh.KeyboardInteractiveChallenge,
	) (*ssh.Permissions, error) {
		/* Ask for a password */
		as, err := client(
			"",
			"",
			[]string{fmt.Sprintf(
				"%v@%v's password:",
				conn.User(),
				hostname,
			)},
			[]bool{false},
		)
		if nil != err {
			return nil, err
		}
		/* Check it */
		if 1 != len(as) {
			logAttempt(conn, "Keyboard", "", false)
		} else {
			p := string(as[0])
			_, ok := passwords[p]
			if !ok && diceRoll(passProb) {
				ok = true
			}
			logAttempt(conn, "Keyboard", p, ok)
			if ok {
				return nil, nil
			}
		}
		return nil, fmt.Errorf(
			"Permission denied, please try again.",
		)
	}
}

/* publicKeyCallback logs that public key auth was attempted. */
func publicKeyCallback() func(
	ssh.ConnMetadata,
	ssh.PublicKey,
) (*ssh.Permissions, error) {
	return func(
		conn ssh.ConnMetadata,
		key ssh.PublicKey,
	) (*ssh.Permissions, error) {
		logAttempt(conn, "Key", fmt.Sprintf(
			"%02X",
			sha256.Sum256(key.Marshal()),
		), false)
		return nil, fmt.Errorf("Permission denied")
	}
}

/* logAttempt logs an authorization attempt. */
func logAttempt(conn ssh.ConnMetadata, method, cred string, suc bool) {
	log.Printf(
		"Address:%v Authorization Attempt Version:%q User:%q %v:%q "+
			"Successful:%v",
		conn.RemoteAddr(),
		string(conn.ClientVersion()),
		conn.User(),
		method,
		cred,
		suc,
	)
}

/* diceRoll will return true with a probability of prob */
func diceRoll(prob float64) bool {
	return rand.Float64() < prob
}
