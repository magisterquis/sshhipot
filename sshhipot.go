package main

/*
 * sshhipot.go
 * High-interaction honeypot, v2
 * By J. Stuart McMurray
 * Created 20180407
 * Last Modified 20180513
 */

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// DEFPORT is the default SSH port
	DEFPORT = "22"
)

func main() {
	var (
		laddr = flag.String(
			"listen",
			"0.0.0.0:2222",
			"SSH listen `address`",
		)
		caddr = flag.String(
			"upstream",
			"167.99.192.112:2",
			"Upstream SSH server `address`",
		)
		cuser = flag.String(
			"user",
			"administrator",
			"Upstream SSH server `username`",
		)
		ckeyf = flag.String(
			"client-key", /* TODO: Better name */
			"id_rsa.XXX", /* TODO: Better name */
			"Upstream SSH server key `file`, which will be "+
				"created if it does not exist", /* TODO: Better help */
		)
		hkeyf = flag.String(
			"upstream-hostkey",
			"upstream.pub",
			"Name of `file` with Upstream host key, which will "+
				"be retreived if it does not exist",
		)
		skeyf = flag.String(
			"key",
			"id_rsa.sshhipot",
			"SSH key `file`, which will be created if it "+
				"does not exist",
		)
		logDir = flag.String(
			"logs",
			"logs",
			"Log `directory`",
		)
		maxClients = flag.Uint(
			"max-clients",
			128,
			"Maximum `number` of simultaneous clients to serve",
		)
		version = flag.String(
			"server-version",
			"",
			"SSH server version `banner` which will be the "+
				"upstream server's if unset",
		)
		timeout = flag.Duration(
			"timeout",
			120*time.Second,
			"Connect and handshake `timeout`",
		)
		silentGlobalRequestList = flag.String(
			"silent-global-requests",
			"hostkeys-00@openssh.com",
			"Comma-separated `list` of global requests to not log",
		)
		silentChannelRequestList = flag.String(
			"silent-channel-requests",
			"pty-req,exit-status",
			"Comma-separated `list` of channel requests "+
				"to not log",
		)
		preauthBanner = flag.String(
			"preauth-banner",
			"",
			"Pre-authentication 'banner', which will be "+
				"the upstream server's if unset",
		)
		credsList = flag.String(
			"creds",
			"root:root,"+
				"root:password,"+
				"root:123456,"+
				"admin:password,"+
				"pi:raspberry,"+
				"ubnt:ubnt",
			"Comma-separated `list` of username:password pairs "+
				"to accept from clients",
		)
		logMax = flag.Uint(
			"log-max",
			15*1024*1024,
			"Maximum log size not including the header, "+
				"in `bytes`",
		)
		logFile = flag.String(
			"log-file",
			"",
			"Append log to `file` as well as standard out",
		)
		useSyslog = flag.Bool(
			"syslog",
			false,
			"Log to syslog as well as any other logging outputs",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Proxies connections to the upstream SSH server, writes interactive sessions
to asciicast files.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Set up logging */
	SetLogging(*logFile, *useSyslog)

	/* Validate arguments */
	if 0 == *maxClients {
		log.Fatalf(
			"Maximum number of clients (-max-clients) " +
				"must be greater than 0",
		)
	}

	/* Validate target address */
	h, p, err := net.SplitHostPort(*caddr)
	if _, ok := err.(*net.AddrError); ok && strings.HasSuffix(
		err.Error(),
		": missing port in address",
	) {
		*caddr = net.JoinHostPort(*caddr, DEFPORT)
		p = DEFPORT
		err = nil
	} else if nil != err {
		log.Fatalf("Invalid upstream address %q: %v", *caddr, err)
	} else if "" == h || "" == p {
		log.Fatalf("Invalid upstream address %q", *caddr)
	}

	/* Load keys for SSH configs */
	ckey, skey, hkey := LoadOrMakeKeys(*skeyf, *ckeyf, *hkeyf, *caddr)

	/* Make sure we have a version banner */
	if "" == *version {
		if *version, err = getVersion(*caddr); nil != err {
			log.Fatalf(
				"Unable to retreive upstream server's "+
					"version: %v",
				err,
			)
		}
		log.Printf("Using upstream server's version: %q", *version)
	}

	/* Get a preauth banner */
	if "" == *preauthBanner {
		*preauthBanner, err = getPreauthBanner(*caddr, hkey)
		if nil != err {
			log.Fatalf(
				"Unable to retreive upstream server's "+
					"pre-auth banner: %v",
				err,
			)
		}
	}
	if "" != *preauthBanner {
		log.Printf("Pre-auth banner: %q", *preauthBanner)
	}

	/* Listen */
	l, err := net.Listen("tcp", *laddr)
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *laddr, err)
	}
	log.Printf("Listening on %v for SSH connections", l.Addr())
	log.Printf("Will proxy connections to %v", *caddr)

	/* Semaphore, https://github.com/golang/go/wiki/BoundingResourceUse */
	sem := make(chan struct{}, *maxClients)

	/* Parse the silent requests into a slice */
	silentGlobalRequests := parseCommaList(*silentGlobalRequestList)
	silentChannelRequests := parseCommaList(*silentChannelRequestList)

	/* Parse creds into a checkable map */
	creds := parseCreds(*credsList)
	if 0 == len(creds) {
		log.Fatalf("No credential pairs given (-creds)")
	}

	/* Handle */
	for {
		/* Wait if we have too many clients */
		sem <- struct{}{}
		/* Accept a client */
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Unable to accept new connections: %v", err)
		}
		/* Handle client */
		go Handle(
			c,
			skey,
			ckey,
			hkey,
			*cuser,
			*version,
			*caddr,
			*timeout,
			func() { <-sem },
			*logDir,
			silentGlobalRequests,
			silentChannelRequests,
			*preauthBanner,
			creds,
			*logMax,
		)
	}
}

/* getVersion gets the upstream server's version banner. */
func getVersion(caddr string) (string, error) {
	/* Connect to the server */
	c, err := net.Dial("tcp", caddr)
	if nil != err {
		return "", err
	}
	defer c.Close()

	/* Read lines until we find it */
	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		l := scanner.Text()
		if strings.HasPrefix(l, "SSH-") {
			return l, nil
		}
	}
	if err := scanner.Err(); nil != err {
		return "", err
	}

	/* Didn't find one */
	return "", errors.New("no banner sent by server")
}

/* getPreauthBanner gets the upstream server's version banner */
func getPreauthBanner(caddr string, hkey ssh.PublicKey) (string, error) {
	var banner string
	/* Connect to the upstream server.  It should probably fail. */
	c, err := ssh.Dial("tcp", caddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.FixedHostKey(hkey),
		BannerCallback: func(m string) error {
			banner = m
			return nil
		},
	})
	if nil != c {
		c.Close()
	}
	/* Ignore auth failed errors */
	if "ssh: handshake failed: ssh: unable to authenticate, "+
		"attempted methods [none], no supported methods remain" ==
		err.Error() {
		err = nil
	}
	return banner, err
}

/* parseCommaList turns a list like foo,bar,tridge into a map, cleaning
whitespace and eliding runs of commas. */
func parseCommaList(l string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, v := range strings.Split(l, ",") {
		v = strings.TrimSpace(v)
		if "" == v {
			continue
		}
		m[v] = struct{}{}
	}
	return m
}

/* parseCreds parses a comma-separated username:password list into a
username->passwords map for authenticating connecting clients. */
func parseCreds(l string) map[string]map[string]struct{} {
	ret := make(map[string]map[string]struct{})
	/* Split into a list of cred pairs */
	pairs := parseCommaList(l)
	/* Add each pair to the map */
	for pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if 2 != len(parts) {
			log.Fatalf("Invalid credential pair %q", pair)
		}
		/* Make sure we have a password map for the username */
		m, ok := ret[parts[0]]
		if !ok {
			m = make(map[string]struct{})
			ret[parts[0]] = m
		}
		/* Add the password to the set of allowed passwords for the
		user. */
		m[parts[1]] = struct{}{}
	}
	return ret
}
