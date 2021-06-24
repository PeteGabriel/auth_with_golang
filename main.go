package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {

	app := new(Application)
	app.auth.username = os.Getenv("USERNAME")
	app.auth.password = os.Getenv("PASSWORD")

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}
	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/unprotected", app.unprotectedHandler)
	mux.HandleFunc("/protected", app.protectedHandler)

    srv := &http.Server{
    	Addr: ":4000",
    	Handler: mux,
    	IdleTimeout: time.Minute,
    	ReadTimeout: 10 * time.Second,
    	WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting server on %s\n", srv.Addr)
    err := srv.ListenAndServeTLS("./localhost.pem", "./localhost-key.pem")
    log.Fatal(err)
}

type Application struct {
	auth struct {
		username, password string
	}
}

func (app *Application) unprotectedHandler(writer http.ResponseWriter, request *http.Request) {
	fmt.Fprintln(writer, "This is the unprotected handler")
}

func (app *Application) protectedHandler(writer http.ResponseWriter, request *http.Request) {
	fmt.Fprintln(writer, "This is the protected handler")
}

func (app *Application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {

		username, password, ok := request.BasicAuth()
		if !ok {
			writer.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}
		unHash := sha256.Sum256([]byte(username))
		pwHash := sha256.Sum256([]byte(password))
		expectedUnHash := sha256.Sum256([]byte(app.auth.username))
		expectedPwHash := sha256.Sum256([]byte(app.auth.password))

		//ConstantTimeCompare provides safety against timing attacks
		usernameMatch := subtle.ConstantTimeCompare(unHash[:], expectedUnHash[:]) == 1
		passwordMatch := subtle.ConstantTimeCompare(pwHash[:], expectedPwHash[:]) == 1

		if usernameMatch && passwordMatch {
			next.ServeHTTP(writer, request)
			return
		}

	}
}
