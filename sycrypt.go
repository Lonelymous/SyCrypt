package sycrypt

import (
	"crypto/sha256"
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

// Salt password and return with salted password and salt
func DynamicSaltPassword(password string) (string, string) {
	halfPassword := len(password) / 2
	if len(password)%2 != 0 {
		halfPassword += 1
	}
	randomSalt := RandomString(halfPassword)
	saltedPassword := SaltPassword(password, randomSalt)
	return saltedPassword, randomSalt
}

// Salt password and hash it and return with hash and salt
func DynamicSaltAndHashPassword(password string) (string, string) {
	saltedPassword, salt := DynamicSaltPassword(password)
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
	hash := sha256.Sum256([]byte(pwd))
	return string(hash[:])
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
