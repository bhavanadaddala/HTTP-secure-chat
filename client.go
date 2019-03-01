package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

//EncryptWithPublicKey encrypts data with a public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		fmt.Println(err)
	}
	return ciphertext
}

func main() {

	//reader := rand.Reader

	resp, err := http.Get("http://localhost:8080/pubkey")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	pubKey, err := ioutil.ReadAll(resp.Body)
	//fmt.Println(pubKey)

	block, rest := pem.Decode(pubKey)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("rest is", rest)

	//Encrypt using PublicKey
	data := []byte("I")
	enc := EncryptWithPublicKey(data, pub.(*rsa.PublicKey))

	res, err := http.PostForm("http://localhost:8080/decrypt", url.Values{"cipher": {string(enc)}})
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	plaintext, err := ioutil.ReadAll(res.Body)
	fmt.Println(string(plaintext))

}
