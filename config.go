package main

/*
 * config.go
 * SSH server config
 * By J. Stuart McMurray
 * Created 20180407
 * Last Modified 20180512
 */

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// KEYLEN is the size of a generated private key
const KEYLEN = 2048

// ErrPermissionDenied is returned from ssh.ServerConfig.PasswordCallback if
// The username and password aren't allowed.
var ErrPermissionDenied = errors.New("permission denied")

// LoadOrMakeKeys returns a client key and a server key, suitable for an
// *ssh.ClientConfig and an *ssh.ServerConfig, respectively, as well as a host
// key, suitable for a HostKeyCallback.  It terminates the program on error.
// The names for the server and client key files are skf and ckf, respectively,
// and the upstream server's host key file is hkf.  If hkf does not exist, the
// key will be retreived from server (i.e. TOFU).
func LoadOrMakeKeys(
	skf string,
	ckf string,
	hkf string,
	server string,
) (ckey, skey ssh.Signer, hkey ssh.PublicKey) {
	/* Load or make Server public */
	sk, made, err := makeOrGetKey(skf)
	if nil != err {
		log.Fatalf("Unable to make or get server key: %v", err)
	}
	if made {
		log.Printf("Wrote server key to %v", skf)
	} else {
		log.Printf("Read server key from %v", skf)
	}

	/* Log the fingerprints */
	log.Printf(
		"Server key fingerprint (MD5): %v",
		ssh.FingerprintLegacyMD5(sk.PublicKey()),
	)
	log.Printf(
		"Server key fingerprint (SHA256): %v",
		ssh.FingerprintSHA256(sk.PublicKey()),
	)

	/* Load or make client key */
	ck, made, err := makeOrGetKey(ckf)
	if nil != err {
		log.Fatalf("Unable to make or get client key: %v", err)
	}
	if made {
		log.Printf("Wrote client key to %v", ckf)
	} else {
		log.Printf("Read client key from %v", ckf)
	}

	/* Get upstream server host key */
	uk, got, err := getServerKey(hkf, server)
	if nil != err {
		log.Fatalf("Unable to get upstream server host key: %v", err)
	}
	if got {
		log.Printf(
			"Retrieved upstream host key from %v "+
				"and wrote it to %v",
			server,
			skf,
		)
	} else {
		log.Printf("Read upstream host key from %v", skf)
	}

	return sk, ck, uk
}

// MakeServerConfig makes an SSH config defining the local server.
func MakeServerConfig(
	tag string,
	key ssh.Signer,
	version string,
	banner string,
	creds map[string]map[string]struct{},
) *ssh.ServerConfig {
	/* Config to return */
	conf := &ssh.ServerConfig{
		Config: ssh.Config{Ciphers: []string{
			/* Enable ALL the ciphers */
			"aes128-gcm@openssh.com",
			"chacha20-poly1305@openssh.com",
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
			"arcfour128",
			"arcfour256",
			"arcfour",
			"aes128-cbc",
			"3des-cbc",
		}},
		PasswordCallback: func(
			conn ssh.ConnMetadata,
			password []byte,
		) (*ssh.Permissions, error) {
			var ok bool
			/* Log the auth attempt */
			defer func() {
				var work string
				if !ok {
					work = " (failed)"
				}
				log.Printf(
					"[%v] Authenticaton %q / %q%v",
					tag,
					conn.User(),
					string(password),
					work,
				)
			}()
			/* Get the allowed passwords for the user */
			m, ok := creds[conn.User()]
			if !ok {
				return nil, ErrPermissionDenied
			}
			/* See if we know this password */
			_, ok = m[string(password)]
			if !ok {
				return nil, ErrPermissionDenied
			}
			return nil, nil
		},
		ServerVersion: version,
		/* Send the banner, and also log that a client has connected */
		BannerCallback: func(m ssh.ConnMetadata) string {
			log.Printf(
				"[%v] Connected (%v)",
				tag,
				string(m.ClientVersion()),
			)
			return banner
		},
	}
	conf.AddHostKey(key)

	return conf
}

// MakeClientConfig makes a config for the connection to the upstream server.
// It takes the username and version string to use, as well as the key with
// which to authenticate to the upstream server and the upstream server's host
// key.
func MakeClientConfig(
	user string,
	version string,
	pk ssh.Signer,
	sk ssh.PublicKey,
) *ssh.ClientConfig {
	conf := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(pk)},
		HostKeyCallback: ssh.FixedHostKey(sk),
		ClientVersion:   version,
	}
	return conf
}

/* makeOrGetKey returns the contents of the file kf if it exists and contains a
valid key or makes it and stores a key in it if it doesn't.  The returned bool
is true if the key was made. */
func makeOrGetKey(kf string) (ssh.Signer, bool, error) {
	/* If the file doesn't exist, stick a key in it */
	if _, err := os.Stat(kf); os.IsNotExist(err) {
		k, err := generateKey(kf)
		return k, true, err
	} else if nil != err {
		return nil, false, err
	}

	/* Read the key from the file */
	b, err := ioutil.ReadFile(kf)
	if nil != err {
		return nil, false, err
	}

	k, err := ssh.ParsePrivateKey(b)
	return k, false, err
}

/* generateKey generates an RSA SSH key, stores it in the file named kf, and
returns it. */
func generateKey(kf string) (ssh.Signer, error) {
	/* Make a key */
	privateKey, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		return nil, err
	}
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := pem.EncodeToMemory(&privateKeyBlock)
	/* Write key to the file */
	if err := ioutil.WriteFile(kf, privateKeyPem, 400); nil != err {
		return nil, err
	}
	/* Make a public key, write to file */
	pkb := privateKey.PublicKey
	pub, err := ssh.NewPublicKey(&pkb)
	if nil != err {
		return nil, err
	}
	if err := ioutil.WriteFile(
		kf+".pub",
		ssh.MarshalAuthorizedKey(pub),
		0644,
	); nil != err {
		return nil, err
	}

	/* Load it in useable form */
	k, err := ssh.ParsePrivateKey(privateKeyPem)
	return k, err
}

/* getServerKey tries to read a public key from skf, and failing that gets the
key from t and writes it to hkf before returning it.  The returned bool is true
if the key was retreived from t. */
func getServerKey(skf, t string) (ssh.PublicKey, bool, error) {
	/* Try to read the key */
	k, err := ioutil.ReadFile(skf)
	if nil != err {
		/* Make the key if we didn't have the file */
		if os.IsNotExist(err) {
			k, err := getServerKeyFromServer(skf, t)
			return k, true, err
		}
		return nil, false, err
	}

	/* Parse the key */
	pk, _, _, _, err := ssh.ParseAuthorizedKey(k)
	return pk, false, err
}

/* getServerKeyFromServer connects to t and writes the server key to skf.  The
handshake is terminated before authentication. */
func getServerKeyFromServer(skf, t string) (ssh.PublicKey, error) {
	var (
		hkey ssh.PublicKey /* Key, if we get it */

		/* Returned error from Dial which means we got the key */
		gotKey = errors.New("sshhipot got correct host key")
	)

	/* Connect to the server to get the key */
	_, err := ssh.Dial("tcp", t, &ssh.ClientConfig{
		HostKeyCallback: func(
			hostname string,
			remote net.Addr,
			key ssh.PublicKey,
		) error {
			hkey = key
			return gotKey
		},
	})

	/* The error's only an error if we didn't get the key */
	if fmt.Sprintf("ssh: handshake failed: %v", gotKey) != err.Error() {
		if nil == err { /* Should never happen */
			panic("made full SSH connection while getting key")
		}
		return nil, err
	}

	/* Log the fingerprints */
	log.Printf(
		"Upstream server key fingerprint (MD5): %v",
		ssh.FingerprintLegacyMD5(hkey),
	)
	log.Printf(
		"Upstream erver key fingerprint (SHA256): %v",
		ssh.FingerprintSHA256(hkey),
	)

	/* Write the key to the file */
	err = ioutil.WriteFile(skf, ssh.MarshalAuthorizedKey(hkey), 0600)
	return hkey, err
}
