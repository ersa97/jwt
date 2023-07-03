package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

type Users struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Pass     string `json:"pass"`
}

var log_database = []Users{
	{
		Id:       1,
		Username: "ersa",
		Pass:     "1234567890",
	},
	{
		Id:       2,
		Username: "Adinda",
		Pass:     "0987654321",
	},
}

var jwt_key = []byte("-----BEGIN PUBLIC KEY-----\nMFswDQYJKoZIhvcNAQEBBQADSgAwRwJAWrUk4EsXW84HcWcjKgd8vqtkLpLz9/1w\nEktgcN/SdQhy/Z8X5NWVXZP/Kyx5kfH+nxTpRvvaqCZUkzqme7Vh0QIDAQAB\n-----END PUBLIC KEY-----")

var privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type response struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {

	r := mux.NewRouter()

	r.HandleFunc("/signin", signin).Methods("POST")
	r.HandleFunc("/", getAll).Methods("GET")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/auth", auth).Methods("GET")
	http.ListenAndServe(":8000", r)
}

func signin(w http.ResponseWriter, r *http.Request) {
	var newUser Users

	err := json.NewDecoder(r.Body).Decode(&newUser)

	if err != nil {
		json.NewEncoder(w).Encode(response{
			Message: "Create User Unsuccessful",
		})
	}

	publicKey := privateKey.PublicKey

	encryptedBytes, _ := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(newUser.Pass),
		nil)
	pass := string(encryptedBytes)
	newUser.Pass = pass

	newUser.Id = log_database[len(log_database)-1].Id + 1

	log_database = append(log_database, newUser)

	json.NewEncoder(w).Encode(response{
		Message: "Create User Successful",
		Data:    newUser,
	})
}

func getAll(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(response{
		Message: "get All User",
		Data:    log_database,
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var newUser Users
	var EncryptedPass string

	err := json.NewDecoder(r.Body).Decode(&newUser)
	enteredPass := newUser.Pass
	username := newUser.Username

	for _, v := range log_database {
		if v.Username == username {
			EncryptedPass = v.Pass
		}
	}
	EncryptedPassByte := []byte(EncryptedPass)

	if err != nil {
		json.NewEncoder(w).Encode(response{
			Message: "Login Failed",
		})
		return
	}

	decryptedPass, _ := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		EncryptedPassByte,
		nil)

	decryptedPassStr := string(decryptedPass)

	// fmt.Printf("entered %s, decrypt %s", enteredPass, decryptedPass)

	if decryptedPassStr != enteredPass {
		json.NewEncoder(w).Encode(response{
			Message: "Username or Password is invalid",
		})
		return
	}

	expiration := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		Username: newUser.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		claims)

	tokenStr, err := token.SignedString(jwt_key)

	if err != nil {
		json.NewEncoder(w).Encode(response{
			Message: "Login Failed",
		})
		return
	}

	json.NewEncoder(w).Encode(response{
		Message: "Login Successful",
		Data:    tokenStr,
	})

}

func auth(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, "Bearer") {
		json.NewEncoder(w).Encode(response{
			Message: "Token is Invalid",
		})
		return
	}

	user, err := extractToken(authHeader)

	if err != nil {
		json.NewEncoder(w).Encode(response{
			Message: err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(response{
		Message: "Authorized User",
		Data:    user,
	})

}

func extractToken(auth string) (interface{}, error) {
	claims := jwt.MapClaims{}

	tokenStr := strings.Replace(auth, "Bearer ", "", -1)

	fmt.Println(tokenStr)
	fmt.Println(claims)

	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			if method, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("signing Method Failed")
			} else if method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("signing Method Failed")
			}
			return jwt_key, nil
		})
	if err != nil {
		return nil, fmt.Errorf("error : %s", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not Valid")
	}
	return claims["user"], nil
}
