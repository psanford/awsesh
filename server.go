package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type server struct {
	creds   *sts.Credentials
	handler http.Handler
}

func (s *server) listenAndServe() error {
	_, err := os.Stat(socketPath())
	if err == nil {
		client := NewClientWithTimeout(1 * time.Second)
		err = client.Ping()
		if err == nil {
			return errors.New("Existing server already running")
		}

		os.Remove(socketPath())
	}

	l, err := net.Listen("unix", socketPath())
	if err != nil {
		return err
	}

	return http.Serve(l, s.handler)
}

func newServer() *server {
	s := &server{}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/assume_role", s.handleAssumeRole)
	mux.HandleFunc("/session", s.handleSession)

	s.handler = mux

	return s
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}

func (s *server) confirmUserPresence(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	confirmStop := make(chan struct{})
	verifyResult := make(chan error)

	go func() {
		ok, err := confirm(childCtx, "Tap yubikey to auth")
		if err != nil {
			log.Printf("confirm err: %s", err)
		}
		if !ok {
			close(confirmStop)
		}
	}()

	go func() {
		err := verifyDevice(childCtx)
		verifyResult <- err
	}()

	select {
	case <-confirmStop:
		return errors.New("user cancelled")
	case authErr := <-verifyResult:
		if authErr != nil {
			return errors.New("yubikey auth error")
		}
	}

	return nil
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := s.confirmUserPresence(ctx)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	optoken, err := opLogin()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "1password login error: %s", err)
		return
	}

	creds, err := getAWSCreds(optoken, conf.OP.Subdomain, conf.OP.Vault, conf.OP.Key)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "1password getAWSCreds error: %s", err)
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, ""),
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	totpCode, err := awsTOTP(ctx)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "TOTP error: %s", err)
		return
	}
	mfaSerial := conf.AWS.MFASerial

	stsService := sts.New(sess)
	out, err := stsService.GetSessionToken(&sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(60 * 60 * 12),
		SerialNumber:    &mfaSerial,
		TokenCode:       &totpCode,
	})

	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "get aws session error: %s", err)
		return
	}

	s.creds = out.Credentials

	fmt.Fprintf(w, "ok!")
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	if s.creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		return
	}

	err := s.confirmUserPresence(r.Context())
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	if s.creds.Expiration.Before(time.Now()) {
		w.WriteHeader(400)
		fmt.Fprintf(w, "creds expired: %s", s.creds.Expiration)
		return
	}

	json.NewEncoder(w).Encode(s.creds)
}

func (s *server) handleAssumeRole(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if s.creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		return
	}

	err := s.confirmUserPresence(r.Context())
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	if s.creds.Expiration.Before(time.Now()) {
		w.WriteHeader(400)
		fmt.Fprintf(w, "creds expired: %s", s.creds.Expiration)
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(*s.creds.AccessKeyId, *s.creds.SecretAccessKey, *s.creds.SessionToken),
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	roleName := r.Form.Get("role_name")
	accountID := r.Form.Get("account_id")
	accountName := r.Form.Get("accountName")
	if accountName == "" {
		accountName = "role"
	}

	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)

	stsService := sts.New(sess)
	out, err := stsService.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String("AWSCLI-Session"),
	})

	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws assumerole error: %s", err)
		return
	}

	json.NewEncoder(w).Encode(out.Credentials)
}

func awsTOTP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ykman", "oath", "code", "aws", "-s").CombinedOutput()

	out = bytes.TrimSpace(out)

	return string(out), err
}
