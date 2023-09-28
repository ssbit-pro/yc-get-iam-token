package main

import (
	"crypto/rsa"
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var keyID string = os.Getenv("IAM_TOKEN_KEY_ID")
var serviceAccountID string = os.Getenv("IAM_TOKEN_SERVICEACCOUNT_ID")
var keyFile string = os.Getenv("IAM_TOKEN_KEYFILE_BASE64")

// Формирование JWT.
func signedToken() string {
	claims := jwt.RegisteredClaims{
		Issuer:    serviceAccountID,
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		Audience:  []string{"https://iam.api.cloud.yandex.net/iam/v1/tokens"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	token.Header["kid"] = keyID

	privateKey := loadPrivateKey()
	signed, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return signed
}

func loadPrivateKey() *rsa.PrivateKey {
	data, err := b64.StdEncoding.DecodeString(keyFile)
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		panic(err)
	}
	return rsaPrivateKey
}

func getIAMToken() string {
	jot := signedToken()
	resp, err := http.Post(
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"jwt":"%s"}`, jot)),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		panic(fmt.Sprintf("%s: %s", resp.Status, body))
	}
	var data struct {
		IAMToken string `json:"iamToken"`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		panic(err)
	}
	return data.IAMToken
}

func help() {
	fmt.Println("Obtaining an IAM token for a service account")
	fmt.Println("---")
	fmt.Println("Required ENV variables:")
	fmt.Println("IAM_TOKEN_KEY_ID: Service Account auth key ID")
	fmt.Println("IAM_TOKEN_SERVICEACCOUNT_ID: Service Account ID")
	fmt.Println("IAM_TOKEN_KEYFILE_BASE64: Service Account private key encoded base64")
}

func main() {
	helpFlag := flag.Bool("h", false, "Show usage information")

	flag.Parse()

	if *helpFlag {
		help()
		os.Exit(0)
	}

	fmt.Println(getIAMToken())
}
