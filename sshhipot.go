package main

/* sshhipot.go
 * High-interaction SSH MitM honeypot
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

/* Verbose Logging */
var verbose func(string, ...interface{})

func main() {
	var (
		/* Listen Address */
		addr = flag.String(
			"a",
			"127.0.0.1:22222",
			"Listen `address`",
		)
		verstr = flag.String(
			"ver",
			"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2",
			"SSH server `version` string",
		)
		keyFile = flag.String(
			"key",
			"sshhipot.id_rsa",
			"SSH private key `file`, which will be created if "+
				"it does not exist",
		)
		noAuth = flag.Bool(
			"noauth",
			false,
			"Allow clients to connect without authenticating",
		)
		passList = flag.String(
			"plist",
			"123456,password,football,qwerty",
			"Comma-separated list of allowed `passwords`",
		)
		passFile = flag.String(
			"pfile",
			"",
			"Name of `file` with password or username:password "+
				"pairs, one per line",
		)
		passProb = flag.Float64(
			"prob",
			0.2,
			"If set, auth attempts will be successful with the "+
				"given `probability` between 0 and 1",
		)
		noSavePass = flag.Bool(
			"nosave",
			false,
			"Don't save passwords randomly accepted when -prob "+
				"is set to >0, otherwise allow reuse of "+
				"randomly accepted passwords",
		)
		userList = flag.String(
			"ulist",
			"root,admin",
			"Comma-separated list of allowed `users`",
		)
		verWL = flag.String(
			"vw",
			"",
			"If set, only these comma-separated SSH client "+
				"`versions` (which may be prefixes ending "+
				"in *) will be allowed (whitelisted, lower "+
				"precedence than -vb)",
		)
		verBL = flag.String(
			"vb",
			"",
			"If set, clients presenting these SSH client "+
				"`versions` (which may be prefixes ending in "+
				"*) will not be allowed to authenticate "+
				"(blacklisted, higher precedence than -vw)",
		)
		verb = flag.Bool(
			"v",
			false,
			"Enable verbose logging",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

MitM's SSH connections and logs all activity.  Options are:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Add microseconds to logging. */
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	/* Enable verbose logging if need be */
	if *verb {
		verbose = log.Printf
	} else {
		verbose = func(f string, a ...interface{}) { return }
	}

	/* Make the server config */
	conf := makeConfig(
		*verWL,
		*verBL,
		*noAuth,
		*userList,
		*passList,
		*passFile,
		*passProb,
		*noSavePass,
		*verstr,
		*keyFile,
	)

	/* Listen */
	l, err := net.Listen("tcp", *addr)
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *addr, err)
	}

	/* Handle clients */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Unable to accept clients: %v", err)
		}
		go handle(c, conf)
	}
}
