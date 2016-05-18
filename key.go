package main

/*
 * key.go
 * Get or make a key
 * By J. Stuart McMurray
 * Created 20160515
 * Last Modified 20160515
 */

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

/* getKey either gets or makes an SSH key from/in the file named f.  generated
will be true if the key was generated during the call. */
func getKey(f string) (key ssh.Signer, generated bool, err error) {
	/* Try to read the key the easy way */
	b, err := ioutil.ReadFile(f)
	if nil == err {
		k, err := ssh.ParsePrivateKey(b)
		return k, false, err
	}
	/* Try to make a key */
	/* Code stolen from http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key */
	privateKey, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		return nil, false, err
	}
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := pem.EncodeToMemory(&privateKeyBlock)
	/* Write key to the file */
	if err := ioutil.WriteFile(f, privateKeyPem, 400); nil != err {
		return nil, false, err
	}

	/* Make a public key, write to file */
	pkb := privateKey.PublicKey
	pub, err := ssh.NewPublicKey(&pkb)
	if nil != err {
		return nil, false, err
	}
	if err := ioutil.WriteFile(
		f+".pub",
		ssh.MarshalAuthorizedKey(pub),
		0644,
	); nil != err {
		return nil, false, err
	}

	/* Load it in useable form */
	k, err := ssh.ParsePrivateKey(privateKeyPem)
	return k, true, err
}
