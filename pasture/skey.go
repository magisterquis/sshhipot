package main

/*
 * skey.go
 * Handle the server's key
 * By J. Stuart McMurray
 * Created 20160122
 * Last Modified 20160122
 */

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

/* serverKey gets or makes a server key, possibly reading it from pkf */
func serverKey(pkf string) (ssh.Signer, error) {
	/* Try to open the private key file */
	privateKeyFile, err := os.OpenFile(pkf, os.O_RDWR|os.O_CREATE, 0600)
	if nil != err {
		return nil, err
	}
	defer privateKeyFile.Close()

	/* Read the file's contents */
	pkb, err := ioutil.ReadAll(privateKeyFile)
	if nil != err {
		return nil, err
	}
	/* If the file was empty, make a key, write the file */
	if 0 == len(pkb) {
		pkb, err = makeKeyInFile(privateKeyFile)
		if nil != err {
			return nil, err
		}
	} else {
		verbose("Read SSH key file %v", pkf)
	}
	/* Parse the key */
	pk, err := ssh.ParsePrivateKey(pkb)
	if nil != err {
		return nil, err
	}
	return pk, nil
}

/* makeKeyInFile makes a private SSH key and writes it to the file f, and
 * returns what it wrote to the file. */
func makeKeyInFile(f *os.File) ([]byte, error) {
	/* Below code mooched from
	 * http://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key */
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	/* Encode the key */
	pkb := pem.EncodeToMemory(privateKeyPEM)

	/* Try to write it to the file */
	if _, err := f.Write(pkb); nil != err {
		return nil, err
	}
	verbose("Made SSH key and wrote it to %v", f.Name())

	/* Return the bytes */
	return pkb, nil
}
