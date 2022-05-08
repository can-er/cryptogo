package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"fmt"
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

func decryptFile(filename string, passphrase string) []byte {
	// Decrypt the file content
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func main() {
	//fmt.Println("Starting the application...")
	//ciphertext := encrypt([]byte("test"), "password")
	//fmt.Printf("Encrypted: %x\n", ciphertext)
	//plaintext := decrypt(ciphertext, "password")
	//fmt.Printf("Decrypted: %s\n", plaintext)
	//encryptFile("sample.txt", []byte("foo"), "password1")
	//fmt.Println(string(decryptFile("sample.txt", "password1")))

	var dir = os.Args[1]
	files, err := ioutil.ReadDir(dir)

	if err != nil {
		log.Fatal(err)
	}

	// Loop through the files to decrypt
	for i := 0; i < len(files); i++ {
		var filePath = dir + "/" + string(files[i].Name())
		fmt.Println(string(decryptFile(filePath, "password1")))
	}

}
