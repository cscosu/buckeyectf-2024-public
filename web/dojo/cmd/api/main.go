package main

import (
	"dojo/internal/server"
	"fmt"
	"log"
	"os"

	"github.com/go-chi/jwtauth/v5"
)

var tokenAuth *jwtauth.JWTAuth

func main() {
	jwtSecret, exists := os.LookupEnv("JWT_SECRET")
	if !exists {
		jwtSecret = "no-secret-set"
		log.Default().Printf("*** JWT_SECRET not set, defaulting to %s ***", jwtSecret)
	}
	tokenAuth = jwtauth.New("HS256", []byte(jwtSecret), nil)
	server.TokenAuth = tokenAuth

	server := server.NewServer()

	err := server.ListenAndServe()
	if err != nil {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
}
