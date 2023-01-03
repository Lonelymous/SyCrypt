package sycrypt

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// RandomString returns a random string with the length of n
func RandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Salt password with a dynamic length salt and return salted password with salt
func DynamicSaltPassword(password string) (string, string) {
	halfPassword := len(password) / 2
	if len(password)%2 != 0 {
		halfPassword += 1
	}
	randomSalt := RandomString(halfPassword)
	saltedPassword := SaltPassword(password, randomSalt)
	return saltedPassword, randomSalt
}

// Salt password with a dynamic length salt and hash it and return hash with salt
func DynamicSaltAndHashPassword(password string) (string, string) {
	saltedPassword, salt := DynamicSaltPassword(password)
	return HashPassword(saltedPassword), salt
}

// Salt password with a fixed length salt and return salted password with salt
func StaticSaltPassword(password string, saltLength int) (string, string) {
	halfPassword := len(password) / 2
	if len(password)%2 != 0 {
		halfPassword += 1
	}
	randomSalt := RandomString(saltLength)
	saltedPassword := SaltPassword(password, randomSalt)
	return saltedPassword, randomSalt
}

// Salt password with a fixed length salt and hash it and return hash with salt
func StaticSaltAndHashPassword(password string, saltLength int) (string, string) {
	saltedPassword, salt := StaticSaltPassword(password, saltLength)
	return HashPassword(saltedPassword), salt
}

// Salt password with the salt and return with the value
func SaltPassword(password, salt string) string {
	saltedPassword := ""
	saltIndex := 0
	for passwordIndex := 0; passwordIndex < len(password); passwordIndex++ {
		if passwordIndex%2 == 0 {
			saltedPassword += string(salt[saltIndex])
			saltIndex++
		}
		saltedPassword += string(password[passwordIndex])
	}
	return saltedPassword
}

// Salt password and hash it and return with the value
func SaltAndHashPassword(password, salt string) string {
	return HashPassword(SaltPassword(password, salt))
}

// Hash password and return with the value
func HashPassword(pwd string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(pwd)))
}

// Verify password with the hash
func VerifyPassword2Hash(hash, password, salt string) bool {
	return hash == SaltAndHashPassword(password, salt)
}

// Verify salted password with the hash
func VerifySaltedPassword2Hash(hash, saltedPassword string) bool {
	return hash == HashPassword(saltedPassword)
}

// Verify hashed password with the hash
func VerifyHash2Hash(hash, hashedPassword string) bool {
	return hash == hashedPassword
}

func encrypt(a, b byte) byte {
	// c := a + b
	// return (c * c) >> 1
	return a << 1
}

func decrypt(a, b byte) byte {
	// c := a << 1
	// return c/c - b
	return a >> 1
}

func magic(a byte) byte {
	return (a + 64) % 128
}

func CryptPassword(password string) string {
	p := ""
	for passwordIndex := 0; passwordIndex < len(password); passwordIndex++ {
		p += string(magic(password[passwordIndex]))
	}
	return p
}

func EncryptPassword(password, secretKey string) string {
	encryptedPassword := ""
	for passwordIndex := 0; passwordIndex < len(password); passwordIndex++ {
		secretKeyIndex := secretKey[passwordIndex%len(secretKey)]
		byt := encrypt(password[passwordIndex], secretKeyIndex)
		encryptedPassword += string(byt)
	}
	return encryptedPassword
}

func DecryptPassword(decryptedPassword, secretKey string) string {
	password := ""
	for decryptedPasswordIndex := 0; decryptedPasswordIndex < len(decryptedPassword); decryptedPasswordIndex++ {
		secretKeyIndex := secretKey[decryptedPasswordIndex%len(secretKey)]
		byt := decrypt(decryptedPassword[decryptedPasswordIndex], secretKeyIndex)
		password += string(byt)
	}
	return password
}
