package sycrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	mathrand "math/rand"
	"os"
	"time"

	"github.com/google/uuid"
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// RandomString returns a random string with the length of n
func RandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mathrand.Intn(len(letterRunes))]
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

// Create Globally Unique Identifier (GUID)
func CreateGUID() string {
	return uuid.New().String()
}

// Create Hash by GUID
func CreateRandomHash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(CreateGUID())))
}

// Create Hash by data
func CreateHash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

// Create Public Key by Random Hash
func CreateAsymmetricKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	// generate key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	return privateKey, &privateKey.PublicKey
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(text []byte, publicKey *rsa.PublicKey) []byte {
	hash := sha512.New()
	encodedText, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, text, nil)
	if err != nil {
		fmt.Println("Error from encryption: ", err.Error())
	}
	return encodedText
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(encodedText []byte, privateKey *rsa.PrivateKey) []byte {
	hash := sha512.New()
	decodedText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, encodedText, nil)
	if err != nil {
		fmt.Println("Error from decryption: ", err.Error())
	}
	return decodedText
}
