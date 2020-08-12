package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const kek1 = "somekeysomekeysomekeysomekeyabcd"

func main() {
	file, err := os.Open("./result")
	defer file.Close()

	if err != nil {
		fmt.Println(err)
	}

	c, err := aes.NewCipher([]byte(kek1))
	if err != nil {
		fmt.Println(err)
	}

	kekCipher, err := cipher.NewGCM(c)

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	output, err := os.Create("result_decryption")
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
		encryptedLine := decryptLine(line, kekCipher)
		_, err := output.WriteString(encryptedLine)
		if err != nil {
			fmt.Println("write err", err)
		}
	}
	output.Sync()
}

func decryptLine(line string, kekCipher cipher.AEAD) string {
	arr := strings.Split(line, " ")
	encryptedData, encryptedDek := arr[0], arr[1]
	dek := decryptString(kekCipher, encryptedDek)
	c, err := aes.NewCipher([]byte(dek))
	if err != nil {
		fmt.Println(err)
	}

	dekGcm, err := cipher.NewGCM(c)
	data := decryptString(dekGcm, encryptedData)
	return data
}

func decryptString(gcm cipher.AEAD, text string) string {
	decodeString, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fmt.Println(err)
	}
	return decrypt(gcm, decodeString)
}

func decrypt(gcm cipher.AEAD, text []byte) string {
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := text[:nonceSize], text[nonceSize:]
	open, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(open)
}
