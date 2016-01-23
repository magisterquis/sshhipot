package main

/*
 * sconfig.go
 * Server Config
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

var (
	/* Users with no particular passwords */
	allowedUsers map[string]bool
	/* Passwords allowed for everybody */
	allowedPasswords map[string]bool
	/* Passwords allowed per-user */
	allowedUserPasswords map[string]map[string]bool
	/* Probability any password will be accepted */
	allowedRandProb float64
	/* Version black/whitelists */
	verBlackList []string
	verWhiteList []string
	/* Save allowed (random) passwords */
	saveAllowedPasswords bool
	/* Name to report as the victim name */
	ourName string
	/* List of known version strings */
	allowedVersions map[string]bool
)

/* makeConfig makes an SSH server config */
func makeConfig(
	verWL string,
	verBL string,
	noAuth bool,
	userList string,
	passList string,
	passFile string,
	passProb float64,
	noSavePass bool,
	verstr string,
	keyFile string,
) *ssh.ServerConfig {
	/* Handle password file */
	var err error
	allowedUsers, allowedPasswords, err = parsePassFile(passFile)
	if nil != err {
		log.Fatalf(
			"Unable to parse per-user passwords from %v: %v",
			passFile,
			err,
		)
	}

	/* Allowed users */
	u := strings.Split(userList, ",")
	if !(1 == len(u) && "" == u[0]) {
		for _, v := range u {
			allowedUsers[v] = true
		}
	}

	/* Split password list */
	p := strings.Split(passList, ",")
	if !(1 == len(p) && "" == p[0]) {
		for _, v := range p {
			allowedPasswords[v] = true
		}
	}

	/* Report on what we have so far */
	if 0 != len(allowedUsers) {
		verbose("Allowed users: %q", mapKeys(allowedUsers))
	}
	if 0 != len(allowedPasswords) {
		verbose("Allowed passwords: %q", mapKeys(allowedPasswords))
	}
	if 0 != len(allowedUserPasswords) {
		verbose(
			"Allowed per-user passwords: %v",
			mapMapString(allowedUserPasswords),
		)
	}

	/* TODO: Ensure the version black/whitelists don't block everything */

	/* Parse black/whitelists */
	if "" != verWL {
		verWhiteList = strings.Split(verWL, ",")
	} else {
		verWhiteList = []string{}
	}
	if 0 != len(verWhiteList) {
		verbose("Version whitelist: %q", verWhiteList)
	}
	if "" != verBL {
		verBlackList = strings.Split(verBL, ",")
	} else {
		verBlackList = []string{}
	}
	if 0 != len(verBlackList) {
		verbose("Version blacklist: %q", verBlackList)
	}

	/* Make sure the password probability is in range */
	if 0 > passProb {
		log.Fatalf("Password probability must not be negative")
	}
	if 1 < passProb {
		log.Fatalf("Password probability must not be greater than 1")
	}
	allowedRandProb = passProb
	if 0 != allowedRandProb {
		verbose(
			"Unexpected passwords will be accepted with a "+
				"probability of %v",
			allowedRandProb,
		)
	}

	/* Whether or not to save allowed random passwords */
	saveAllowedPasswords = !noSavePass
	if !saveAllowedPasswords {
		verbose("Not saving randomly-accepted passwords")
	}

	/* Config struct to return */
	conf := &ssh.ServerConfig{
		NoClientAuth: noAuth,
		PasswordCallback: func(
			conn ssh.ConnMetadata,
			password []byte,
		) (*ssh.Permissions, error) {
			return decidePassword(conn, password, "password")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			client ssh.KeyboardInteractiveChallenge,
		) (*ssh.Permissions, error) {
			/* Ask for a password */
			a, err := client(
				conn.User(),
				"",
				[]string{fmt.Sprintf(
					"%v's password: ",
					conn.User(),
				)},
				[]bool{false},
			)
			if nil != err {
				log.Printf(
					"%v InteractiveError:%q",
					ci(conn),
					err.Error(),
				)
				return nil, err
			}
			/* No answer? */
			if 0 == len(a) {
				log.Printf(
					"%v NoAuthAnswer",
					ci(conn),
				)
				return nil, fmt.Errorf("Nothing")
			}
			/* Decide the usual way */
			return decidePassword(
				conn,
				[]byte(a[0]),
				"keyboard-interactive",
			)
		},
		/* Log but don't allow public keys */
		PublicKeyCallback: func(
			conn ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			log.Printf(
				"%v Key(%v):%02X",
				ci(conn),
				key.Type(),
				md5.Sum(key.Marshal()),
			)
			return nil, fmt.Errorf("invalid key")
		},
		/* Log connections with no auth */
		AuthLogCallback: func(
			conn ssh.ConnMetadata,
			method string,
			err error) {
			/* only care about authless connects */
			if "none" != method {
				return
			}
			if nil != err {
				log.Printf("%v NoAuthFail", ci(conn))
				return
			}
			log.Printf("%v NoAuthFail", ci(conn))
		},
		/* Version string for the server */
		ServerVersion: verstr,
	}

	/* Add the server key to the config */
	k, err := serverKey(keyFile)
	if nil != err {
		log.Fatalf(
			"Unable to read key from or make key in %v: %v",
			keyFile,
			err,
		)
	}
	conf.AddHostKey(k)
	return conf

	/* TODO: Make sure there's a way to log in.  len(u) != 0 || len(aup) != 0, such */
}

/* parsePassFile parses a user:password file and returs per-user passwords and
globally-allowed passwords and globally-allowed usernames. */
func parsePassFile(fn string) (
	users map[string]bool,
	passes map[string]bool,
	err error,
) {
	users = map[string]bool{}
	passes = map[string]bool{}

	/* If there's no file, give up */
	if "" == fn {
		return
	}

	/* Open the password file */
	f, err := os.Open(fn)
	if nil != err {
		return nil, nil, err
	}
	defer f.Close()

	/* Parse each line */
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		/* Don't bother with empty lines or comments */
		/* TODO: Document that comments are ok */
		if 0 == len(line) ||
			strings.HasPrefix(strings.TrimLeftFunc(
				line,
				unicode.IsSpace,
			), "#") {
			continue
		}

		/* Split the username and password */
		parts := strings.SplitN(scanner.Text(), ":", 2)

		/* Empty line */
		if 0 == len(parts) {
			continue
		}

		/* If we only got one bit or the username's blank, it's a
		password */
		found := true
		if 1 == len(parts) { /* Single password on a line */
			passes[parts[0]] = true
		} else if "" == parts[0] { /* :password */
			passes[parts[1]] = true
		} else if "" == parts[1] { /* username: */
			users[parts[0]] = true
		} else { /* username:password */
			found = false
		}
		if found {
			continue
		}

		/* Append the password to the list of the user's passwords */
		saveUserPass(parts[0], parts[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return
}

/* decidePassword decides whether the connection attempt is allowed and logs
the attempt with the auth type (password, keyboard-interactive). */
func decidePassword(
	conn ssh.ConnMetadata,
	password []byte,
	authType string,
) (*ssh.Permissions, error) {
	/* Check if the version string is on the whitelist */
	/* Check if the version string is on the blacklist */
	/* TODO: Finish these */

	u := conn.User()      /* Username */
	p := string(password) /* Password */
	ua := false           /* User allowed */
	pa := false           /* Password allowed */

	/* Make sure the client's version is allowed */
	if !versionAllowed(string(conn.ClientVersion())) {
		log.Printf("%v VersionFail", ci(conn))
		return nil, fmt.Errorf("version")
	}

	/* Check if the username is allowed */
	if _, ok := allowedUsers[u]; ok {
		ua = true
	}

	/* Check if the password is allowed for all users */
	if _, ok := allowedPasswords[p]; ok {
		pa = true
	}

	/* Check if there's a user-specific password if he's not allowed yet */
	if !ua || !pa {
		if ps, ok := allowedUserPasswords[u]; ok {
			if _, ok := ps[p]; ok {
				ua = true
				pa = true
			}
		}
	}

	/* If there's a random chance, apply it and save the password */
	if !ua || !pa && 0 != allowedRandProb {
		if rand.Float64() < allowedRandProb {
			/* If we're here, we win */
			ua = true
			pa = true
			/* Save if we're meant to */
			if saveAllowedPasswords {
				saveUserPass(u, p)
				verbose("Saved allowed creds: %q / %q", u, p)
			}
		}
	}

	/* If the user's allowed, log it, give up */
	if ua && pa {
		log.Printf("%v Type:%v PasswordOK:%q", ci(conn), authType, p)
		return nil, nil
	}

	/* If not, :( */
	log.Printf("%v Type:%v PasswordFail:%q", ci(conn), authType, p)
	return nil, fmt.Errorf("no")

}

/* mapMapString nicely stringifies a map[string]map[string]bool */
func mapMapString(m map[string]map[string]bool) string {
	/* Output string */
	s := ""
	/* Make a sorted list of keys */
	us := make([]string, len(m))
	i := 0
	for u, _ := range m {
		us[i] = u
		i++
	}
	sort.Strings(us)
	/* Make a nice list of second-map keys */
	for _, u := range us {
		s += u + ":"
		pa := make([]string, len(m[u]))
		i = 0
		for p, _ := range m[u] {
			pa[i] = p
			i++
		}
		s += fmt.Sprintf("%q ", pa)
	}
	return strings.TrimSpace(s)
}

/* mapKeys returns the keys of map m as a sorted []string */
func mapKeys(m map[string]bool) []string {
	a := make([]string, len(m))
	i := 0
	for k, _ := range m {
		a[i] = k
		i++
	}
	sort.Strings(a)
	return a
}

/* saveUserPass saves the user-specific password p for user u */
func saveUserPass(u, p string) {
	if nil == allowedUserPasswords {
		allowedUserPasswords = map[string]map[string]bool{}
	}
	if _, ok := allowedUserPasswords[u]; !ok {
		allowedUserPasswords[u] = map[string]bool{}
	}
	allowedUserPasswords[u][p] = true
}

/* ci returns a string containing info from an ssh.ConnMetadata */
func ci(m ssh.ConnMetadata) string {
	return fmt.Sprintf(
		"Address:%v Target:%v Version:%q User:%q",
		m.RemoteAddr(),
		victimName(m),
		m.ClientVersion(),
		m.User(),
	)
}

/* victimName returns the name of the victim (honeypot) */
func victimName(c ssh.ConnMetadata) string {
	/* Used a cached value */
	if "" != ourName {
		return ourName
	}
	/* Try the hostname first */
	h, err := os.Hostname()
	if nil != err {
		verbose("Unable to determine hostname: %v", err)
		/* Failing that, use the local address */
		return c.LocalAddr().String()
	}
	ourName = h
	return ourName
}

/* versionAllowed returns true if the given version string is allowed */
func versionAllowed(v string) bool {
	/* Make sure we have a map */
	if nil == allowedVersions {
		allowedVersions = map[string]bool{}
	}
	/* If we have a cached answer, return it */
	if a, ok := allowedVersions[v]; ok {
		return a
	}
	/* Assume it's not allowed */
	allowed := false
	/* If there's no whitelist, assume it's allowed */
	if 0 == len(verWhiteList) {
		allowed = true
	}
	/* Check the whitelist */
	for _, vp := range verWhiteList {
		if matchOrHasPrefix(v, vp) {
			allowed = true
			break
		}
	}

	/* If we're not allowed after the whitelist check, we're not allowed.
	 * Cache it and give up. */
	if !allowed {
		allowedVersions[v] = false
		return false
	}

	/* Check the blacklist to make sure we're allowed */
	for _, vp := range verBlackList {
		if matchOrHasPrefix(v, vp) {
			allowed = false
			break
		}
	}

	/* Final answer, cache it */
	allowedVersions[v] = allowed
	return allowed
}

/* matchOrIsPrefix checks if pat is the same as s, or if pat ends in *, if s
 * starts with pat. */
func matchOrHasPrefix(s, pat string) bool {
	/* String equality is easy */
	if !strings.HasSuffix(pat, "*") {
		return s == pat
	}
	/* If it's a prefix, remove the trailing * and check it */
	patr := []rune(pat)       /* Make it a slice of runes */
	patr = patr[:len(patr)-1] /* Remove the last on, the * */
	pat = string(patr)        /* Back to a string */
	return strings.HasPrefix(s, pat)
}
