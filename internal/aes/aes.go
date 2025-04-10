// Package aes provides functions to encrypt and decrypt files using AES algorithm
// using a key from the environment variable or from a file.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KeyLenAES128 is the key length for AES128.
// (128, 192, or 256 bits // 8 bits= one character).
const KeyLenAES128 = 16

// KeyLenAES256 is the key length for AES256.
const KeyLenAES256 = 24

// KeyLenAES512 is the key length for AES512.
const KeyLenAES512 = 32

// ErrEmptyKey is returned when the key is empty or not set.
var ErrEmptyKey = errors.New("key is empty or not set")

// ErrLengthKey is returned when the key length is not 16, 24 or 32 bytes.
// The key should be 16, 24 or 32 bytes long.
var ErrLengthKey = fmt.Errorf("length of key should be %d (AES128), %d (AES256) or %d (AES512)",
	KeyLenAES128, KeyLenAES256, KeyLenAES512)

// GetKey returns the key from the environment variable or from the file
// If the key is not set or empty, it returns an error
// The key should be 16, 24 or 32 bytes long.
func GetKey(keyFilename string) ([]byte, error) {
	var key []byte
	keyFromEnv := os.Getenv("GOCRYPT_KEY")
	keyFromFile, err := getKeyFromFile(keyFilename)
	if err != nil {
		key = []byte(keyFromEnv)
	}
	if err == nil {
		key = keyFromFile
	}
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	return key, nil
}

func getKeyFromFile(keyFilename string) ([]byte, error) {
	key, err := os.ReadFile(keyFilename) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read file err: %w", err)
	}
	keyWithoutCR := strings.Trim(string(key), "\r\n")

	if len(keyWithoutCR) != KeyLenAES128 && len(keyWithoutCR) != KeyLenAES256 && len(keyWithoutCR) != KeyLenAES512 {
		return nil, ErrLengthKey
	}

	return []byte(keyWithoutCR), err
}

// EncryptFile encrypts the file using the key
// The key should be 16, 24 or 32 bytes long.
func EncryptFile(key []byte, inputFile, outputFile string) error {
	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher err: %w", err)
	}
	reader, err := os.Open(inputFile) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open err: %w", err)
	}
	defer func() {
		err = reader.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "close err: %v", err)
		}
	}()

	writer, err := os.Create(outputFile) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create err: %w", err)
	}
	defer func() {
		err = writer.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "close err: %v", err)
		}
	}()

	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewOFB(block, iv)
	cipherWriter := &cipher.StreamWriter{
		S:   stream,
		W:   writer,
		Err: nil,
	}
	if _, err = io.Copy(cipherWriter, reader); err != nil {
		return fmt.Errorf("copy err: %w", err)
	}
	return nil
}

// DecryptFile decrypts the file using the key
// The key should be 16, 24 or 32 bytes long.
func DecryptFile(key []byte, inputFile, outputFile string) error {
	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher err: %w", err)
	}
	reader, err := os.Open(inputFile) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open err: %w", err)
	}
	defer func() {
		err = reader.Close()
		if err != nil {
			fmt.Printf("close err: %v", err)
		}
	}()

	file, err := os.Create(outputFile) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create err: %w", err)
	}
	defer func() {
		err = file.Close()
		if err != nil {
			fmt.Printf("close err: %v", err)
		}
	}()

	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewOFB(block, iv)
	cipherReader := &cipher.StreamReader{S: stream, R: reader}
	if _, err = io.Copy(file, cipherReader); err != nil {
		return fmt.Errorf("copy err: %w", err)
	}

	return nil
}
