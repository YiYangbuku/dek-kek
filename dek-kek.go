package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

const kek = "somekeysomekeysomekeysomekeyabcd"
const keySize = 32

func main() {
	file, err := os.Open("./input")
	defer file.Close()

	if err != nil {
		fmt.Println(err)
	}

	c, err := aes.NewCipher([]byte(kek))
	if err != nil {
		fmt.Println(err)
	}

	kekCipher, err := cipher.NewGCM(c)

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	output, err := os.Create("result")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer output.Close()

	var line string
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("read err", err)
			}
			break
		}
		encryptedLine, encryptedDek := encryptLine(line, kekCipher)
		_, err := output.WriteString(encryptedLine + " " + encryptedDek + "\n")
		if err != nil {
			fmt.Println("write err", err)
		}
	}
	output.Sync()
}

func encryptLine(line string, kekCipher cipher.AEAD) (string, string) {
	dek := genDek()
	c, err := aes.NewCipher(dek)
	if err != nil {
		fmt.Println(err)
	}

	dekGcm, err := cipher.NewGCM(c)
	encryptedLine := encryptString(dekGcm, line)
	encryptedDek := encrypt(kekCipher, dek)
	return encryptedLine, encryptedDek
}

func genDek() []byte {
	dek := make([]byte, keySize)
	_, err := rand.Read(dek)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return dek
}


func decryptGcm(gcm cipher.AEAD, text string) string {
	nonceSize := gcm.NonceSize()
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fmt.Println(err)
	}
	nonce, ciphertext := bytes[:nonceSize], bytes[nonceSize:]
	open, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(open)
}

func encryptString(gcm cipher.AEAD, text string) string {
	return encrypt(gcm, []byte(text))
}

func encrypt(gcm cipher.AEAD, text []byte) string {
	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, text, nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}
