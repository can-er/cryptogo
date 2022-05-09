package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
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

func decrypt(data []byte, passphrase string) []byte {
	// Create a new AES cipher block
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Create a new nonce
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func decryptFile(filename string, data []byte, passphrase string) {
	// Decrypt the file content
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(decrypt(data, passphrase))
}

func main() {
	// Usage example:
	//fmt.Println("Starting the application...")
	//ciphertext := encrypt([]byte("test"), "password")
	//plaintext := decrypt(ciphertext, "password")
	//fmt.Printf("Decrypted: %s\n", plaintext)
	//fmt.Println(string(decryptFile("sample.txt", "password1")))

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
		decryptFile(filePath, []byte(string(content)), "password1")
	}

}
