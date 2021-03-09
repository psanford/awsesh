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
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/psanford/awsesh/onepassword"
	"github.com/psanford/awsesh/pass"
	"github.com/psanford/awsesh/passprovider"
	"github.com/psanford/awsesh/pinentry"
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
		ok, err := pinentry.Confirm(childCtx, "Tap yubikey to auth")
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

	provider := conf.Provider[0]

	var passProvider passprovider.Provider

	if provider.Type == "op" {
		passProvider = onepassword.New(provider.OP.Subdomain, provider.OP.Vault, provider.OP.Key)
	} else if provider.Type == "pass" {
		passProvider = pass.New(provider.Pass.Path)
	} else {
		log.Printf("Bad provider type: %s", provider.Type)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Bad provider type: %s", provider.Type)
		return
	}

	var totpCode string
	if provider.Type == "pass" {
		// pass+yubikey can messup the totp interface on the yubikey.
		// do totp first just for this case
		totpCode, err = awsTOTP(ctx, provider.AWS.OathName)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "TOTP error: %s", err)
			return
		}
	}

	creds, err := passProvider.AWSCreds()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Get AWSCreds error: %s", err)
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

	if provider.Type != "pass" {
		totpCode, err = awsTOTP(ctx, provider.AWS.OathName)
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "TOTP error: %s", err)
			return
		}
	}

	mfaSerial := provider.AWS.MFASerial

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

	r.ParseForm()
	timeoutSeconds := 60 * 30
	timeoutSecsStr := r.FormValue("timeout_seconds")
	if timeoutSecsStr != "" {
		i, _ := strconv.Atoi(timeoutSecsStr)
		if i > 0 {
			timeoutSeconds = i
		}
	}

	ctx := r.Context()

	err := s.confirmUserPresence(ctx)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	provider := conf.Provider[0]

	var passProvider passprovider.Provider

	if provider.Type == "op" {
		passProvider = onepassword.New(provider.OP.Subdomain, provider.OP.Vault, provider.OP.Key)
	} else if provider.Type == "pass" {
		passProvider = pass.New(provider.Pass.Path)
	} else {
		log.Printf("Bad provider type: %s", provider.Type)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Bad provider type: %s", provider.Type)
		return
	}

	creds, err := passProvider.AWSCreds()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Get AWSCreds error: %s", err)
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

	totpCode, err := awsTOTP(ctx, provider.AWS.OathName)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "TOTP error: %s", err)
		return
	}
	mfaSerial := provider.AWS.MFASerial

	stsService := sts.New(sess)
	out, err := stsService.GetSessionToken(&sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(timeoutSeconds)),
		SerialNumber:    &mfaSerial,
		TokenCode:       &totpCode,
	})

	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "get aws session error: %s", err)
		return
	}

	json.NewEncoder(w).Encode(out.Credentials)
}

func (s *server) handleAssumeRole(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if s.creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		return
	}

	r.ParseForm()
	timeoutSeconds := 60 * 60 * 6
	timeoutSecsStr := r.FormValue("timeout_seconds")
	if timeoutSecsStr != "" {
		i, _ := strconv.Atoi(timeoutSecsStr)
		if i > 0 {
			timeoutSeconds = i
		}
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
		DurationSeconds: aws.Int64(int64(timeoutSeconds)),
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

func awsTOTP(ctx context.Context, oathName string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ykman", "oath", "code", oathName, "-s").CombinedOutput()

	out = bytes.TrimSpace(out)

	return string(out), err
}
