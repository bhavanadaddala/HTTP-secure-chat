package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/gin-gonic/gin"
)

//DecryptWithPrivateKey helps server decrypt data encrypted by client
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext
}

func main() {

	gin.SetMode(gin.ReleaseMode)

	// Generate RSA key pair

	reader := rand.Reader
	bitSize := 2048

	privatekey, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		fmt.Println("the error is", err)
	}

	publickey := privatekey.PublicKey

	PubASN1, err := x509.MarshalPKIXPublicKey(&publickey)
	if err != nil {
		// do something about it
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	})

	r := gin.Default()

	r.GET("/pubkey", func(c *gin.Context) {

		c.String(200, string(pubBytes))

	})

	r.POST("/decrypt", func(c *gin.Context) {

		text := c.PostForm("cipher")

		cp := DecryptWithPrivateKey([]byte(text), privatekey)
		c.String(200, string(cp))

	})

	r.Run(":8080")
}
