package main

/*
 * sshhipot.go
 * Hi-interaction ssh honeypot
 * By J. Stuart McMurray
 * Created 20160514
 * Last Modified 20160605
 */

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	/* Network addresses */
	var laddr = flag.String(
		"l",
		":2222",
		"Listen `address`",
	)
	var noAuthOk = flag.Bool(
		"A",
		false,
		"Allow clients to connect without authentication",
	)
	var serverVersion = flag.String(
		"v",
		"SSH-2.0-OpenSSH_7.2",
		"Server `version` to present to clients",
		/* TODO: Get from real server */
	)
	var password = flag.String(
		"p",
		"hunter2",
		"Allowed `password`",
	)
	var passList = flag.String(
		"pf",
		"",
		"Password `file` with one password per line",
	)
	var passProb = flag.Float64(
		"pp",
		.05,
		"Accept any password with this `probability`",
	)
	var kicHost = flag.String(
		"H",
		"localhost",
		"Keyboard-Interactive challenge `hostname`",
	)
	var keyName = flag.String(
		"k",
		"shp_id_rsa",
		"SSH RSA `key`, which will be created if it does not exist",
	)
	/* Logging */
	var logDir = flag.String(
		"d",
		"conns",
		"Per-onnection log `directory`",
	)
	var hideBanners = flag.Bool(
		"B",
		false,
		"Don't log connections with no authentication attempts (banners).",
	)
	/* Client */
	var cUser = flag.String(
		"cu",
		"root",
		"Upstream `username`",
	)
	var cKey = flag.String(
		"ck",
		"id_rsa",
		"RSA `key` to use as a client, "+
			"which will be created if it does not exist",
	)
	var saddr = flag.String(
		"cs",
		"192.168.0.2:22",
		"Real server `address`",
	)
	/* Local server config */
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Log better */
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)
	/* TODO: Log target server */

	/* Make a server config */
	sc := makeServerConfig(
		*noAuthOk,
		*serverVersion,
		*password,
		*passList,
		*passProb,
		*kicHost,
		*keyName,
	)

	/* Make a client config */
	cc := makeClientConfig(*cUser, *cKey)

	/* Listen for clients */
	l, err := net.Listen("tcp", addSSHPort(*laddr))
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *laddr, err)
	}
	log.Printf("Listening on %v", l.Addr())

	/* Accept clients, handle */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Unable to accept client: %v", err)
		}
		go handle(c, sc, *saddr, cc, *logDir, *hideBanners)
	}
}

/* addSSHPort adds the default SSH port to an address if it has no port. */
func addSSHPort(addr string) string {
	/* Make sure we have a port */
	_, _, err := net.SplitHostPort(addr)
	if nil != err {
		if !strings.HasPrefix(err.Error(), "missing port in address") {
			log.Fatalf(
				"Unable to check for port in %q: %v",
				addr,
				err,
			)
		}
		addr = net.JoinHostPort(addr, "ssh")
	}
	return addr
}

/* TODO: Log to stdout or logfile */
