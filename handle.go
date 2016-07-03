package main

/*
 * handle.go
 * Handle an SSH connection
 * By J. Stuart McMurray
 * Created 20160514
 * Last Modified 20160605
 */

import (
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	LOGFORMAT = "2006-01-02T15.04.05.999999999Z0700"
	LOGNAME   = "log"
)

/* handle handles an incoming connection */
func handle(
	c net.Conn,
	sconfig *ssh.ServerConfig,
	saddr string,
	cconfig *ssh.ClientConfig,
	logDir string,
	hideBanners bool,
) {
	defer c.Close()
	log.Printf("Address:%v New Connection", c.RemoteAddr())

	/* Try to turn it into an SSH connection */
	sc, achans, areqs, err := ssh.NewServerConn(c, sconfig)
	if nil != err {
		/* Done unless we're supposed to report banner-grabbing */
		if hideBanners {
			return
		}
		/* EOF means the client gave up */
		if io.EOF == err {
			log.Printf(
				"Address:%v Pre-Auth Disconnect",
				c.RemoteAddr(),
			)
		} else {
			log.Printf(
				"Address:%v Pre-Auth Error:%q",
				c.RemoteAddr(),
				err,
			)
		}
		return
	}
	defer sc.Close()

	/* Get a logger */
	lg, ln, ld, lf, err := connectionLogger(sc, logDir)
	if nil != err {
		log.Printf(
			"Address:%v Unable to cerate log: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	defer lf.Close()
	log.Printf("Address:%v Log:%q", c.RemoteAddr(), ln)
	lg.Printf("Start of log")

	/* Connect to the real server */
	client, cchans, creqs, err := clientDial(saddr, cconfig)
	if nil != err {
		log.Printf("Unable to connect to %v: %v", saddr, err)
		return
	}
	defer client.Close()
	lg.Printf("Connected to upstream server %v@%v", cconfig.User, saddr)

	/* Handle requests and channels */
	go handleReqs(areqs, client, lg, "attacker->server")
	go handleReqs(creqs, sc, lg, "server->attacker")
	go handleChans(achans, client, ld, lg, "attacker->server")
	go handleChans(cchans, sc, ld, lg, "server->attacker")

	/* Wait for SSH session to end */
	wc := make(chan struct{}, 2)
	go waitChan(sc, wc)
	go waitChan(client, wc)
	<-wc
	log.Printf("Address:%v Finished", c.RemoteAddr())

}

/* connectionLogger opens a log file for the authenticated connection in the
given logDir.  It returns the logger itself, as well as the name of the
logfile and the session directory.  Should look like
	logdir/address/sessiontime/log
The returned *os.File must be closed when it's no longer needed to prevent
memory/fd leakage.
*/
func connectionLogger(
	sc *ssh.ServerConn,
	logDir string,
) (lg *log.Logger, name, dir string, file *os.File, err error) {
	/* Each host gets its own directory */
	addrDir, _, err := net.SplitHostPort(sc.RemoteAddr().String())
	if nil != err {
		log.Printf(
			"Address:%v Unable to split host from port: %v",
			sc.RemoteAddr().String(),
			err,
		)
		addrDir = sc.RemoteAddr().String() + "err"
	}

	/* Each authenticated session does, as well */
	sessionDir := filepath.Join(
		logDir,
		addrDir,
		time.Now().Format(LOGFORMAT),
	)
	if err := os.MkdirAll(sessionDir, 0700); nil != err {
		return nil, "", "", nil, err
	}
	/* Open the main logfile */
	logName := filepath.Join(sessionDir, LOGNAME)
	lf, err := os.OpenFile(
		logName,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if nil != err {
		return nil, "", "", nil, err
	}

	/* Logify it. */
	return log.New(
		//lf,
		io.MultiWriter(lf, os.Stderr), /* DEBUG */
		"",
		log.LstdFlags|log.Lmicroseconds,
	), logName, sessionDir, lf, nil
}

/* waitChan puts an empty struct in wc when c's Wait method returns. */
func waitChan(c ssh.Conn, wc chan<- struct{}) {
	c.Wait()
	wc <- struct{}{}
}
