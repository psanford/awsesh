package main

import (
	"fmt"
	"net/http"
)

type server struct {
	creds *creds
}

type creds struct {
}

func newServer() *server {
	s := &server{}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/login", s.handleLogin)

	return s
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {

}
