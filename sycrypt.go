package sycrypt

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func RandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func DynamicSaltPassword(password string) (string, string) {
	halfPassword := len(password) / 2
	if len(password)%2 != 0 {
		halfPassword += 1
	}
	randomSalt := RandomString(halfPassword)
	saltedPassword := SaltPassword(password, randomSalt)
	return saltedPassword, randomSalt
}

func DynamicSaltAndHashPassword(password string) (string, string) {
	saltedPassword, salt := DynamicSaltPassword(password)
	return HashPassword(saltedPassword), salt
}

func SaltPassword(password string, salt string) string {
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

func SaltAndHashPassword(password string, salt string) string {
	return HashPassword(SaltPassword(password, salt))
}

func HashPassword(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	if err != nil {
		return ""
	}
	return string(hash)
}

func VerifyPassword(password string, salt string, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(SaltPassword(password, salt))) == nil
}

func VerifySaltedPassword(saltedPassword string, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(saltedPassword)) == nil
}
