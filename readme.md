package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

var jwt_key = []byte("test123")

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type response struct {
	Username string      `json:"username"`
	Data     interface{} `json:"data,omitempty"`
}

type rsa_response struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/signin", signin).Methods("POST")
	r.HandleFunc("/welcome", welcome).Methods("GET")
	r.HandleFunc("/refresh", refresh).Methods("POST")
	// r.HandleFunc("/decrypt", decrypting).Methods("GET")
	// r.HandleFunc("/encrypt", encrypting).Methods("POST")
	http.ListenAndServe(":8000", r)

}

func signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedpw, ok := users[creds.Username]

	if !ok || expectedpw != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expiration := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwt_key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expiration,
	})

	json.NewEncoder(w).Encode(response{
		Username: claims.Username,
		Data:     tokenString,
	})
}

func welcome(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	TknStr := c.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(TknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwt_key, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(response{
		Username: fmt.Sprintf("Welcome %s", claims.Username),
	})
}

func refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknstr := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknstr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwt_key, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expiration := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expiration.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenstring, err := token.SignedString(jwt_key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenstring,
		Expires: expiration,
	})

	json.NewEncoder(w).Encode(response{
		Username: claims.Username,
		Data:     tokenstring,
	})
}

// func decrypting(w http.ResponseWriter, r *http.Request) {

// }

func encrypting(w http.ResponseWriter, r *http.Request) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		json.NewEncoder(w).Encode(rsa_response{
			Message: "Generate Key Failed",
		})
	}

	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte("super-duper secret message"),
		nil)

	if err != nil {
		json.NewEncoder(w).Encode(rsa_response{
			Message: "Encryption Failed",
		})
	}

	json.NewEncoder(w).Encode(rsa_response{
		Message: "Data Encrypted",
		Data:    encryptedBytes,
	})

}
