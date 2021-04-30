package server

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
	"github.com/psanford/awsesh/client"
	"github.com/psanford/awsesh/config"
	"github.com/psanford/awsesh/messages"
	"github.com/psanford/awsesh/onepassword"
	"github.com/psanford/awsesh/pass"
	"github.com/psanford/awsesh/passprovider"
	"github.com/psanford/awsesh/pinentry"
	"github.com/psanford/awsesh/u2f"
)

type server struct {
	creds   map[string]*sts.Credentials
	handler http.Handler
	conf    *config.Config
}

func (s *server) ListenAndServe() error {
	_, err := os.Stat(config.SocketPath())
	if err == nil {
		c := client.NewClientWithTimeout(1 * time.Second)
		err = c.Ping()
		if err == nil {
			return errors.New("Existing server already running")
		}

		os.Remove(config.SocketPath())
	}

	l, err := net.Listen("unix", config.SocketPath())
	if err != nil {
		return err
	}

	return http.Serve(l, s.handler)
}

func New(conf *config.Config) *server {
	s := &server{
		creds: make(map[string]*sts.Credentials),
		conf:  conf,
	}

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
		err := u2f.VerifyDevice(childCtx, s.conf.KeyHandle)
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
	r.ParseForm()

	err := s.confirmUserPresence(ctx)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	provider, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	var passProvider passprovider.Provider

	if provider.Provider == "op" {
		passProvider = onepassword.New(provider.OP.Subdomain, provider.OP.Vault, provider.OP.Key)
	} else if provider.Provider == "pass" {
		passProvider = pass.New(provider.Pass.Path)
	} else {
		log.Printf("Bad provider type: %s", provider.Provider)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Bad provider type: %s", provider.Provider)
		return
	}

	var totpCode string
	if provider.Provider == "pass" {
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
		Region:      aws.String(provider.AWS.Region),
		Credentials: credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, ""),
	})
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws new session error: %s", err)
		return
	}

	if provider.Provider != "pass" {
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

	s.creds[provider.ID] = out.Credentials

	fmt.Fprintf(w, "ok!")
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ctx := r.Context()

	timeoutSeconds := 60 * 30
	timeoutSecsStr := r.FormValue("timeout_seconds")
	if timeoutSecsStr != "" {
		i, _ := strconv.Atoi(timeoutSecsStr)
		if i > 0 {
			timeoutSeconds = i
		}
	}

	provider, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	err = s.confirmUserPresence(ctx)
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	var passProvider passprovider.Provider

	if provider.Provider == "op" {
		passProvider = onepassword.New(provider.OP.Subdomain, provider.OP.Vault, provider.OP.Key)
	} else if provider.Provider == "pass" {
		passProvider = pass.New(provider.Pass.Path)
	} else {
		log.Printf("Bad provider type: %s", provider.Provider)
		w.WriteHeader(400)
		fmt.Fprintf(w, "Bad provider type: %s", provider.Provider)
		return
	}

	creds, err := passProvider.AWSCreds()
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Get AWSCreds error: %s", err)
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(provider.AWS.Region),
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

	result := messages.Credentials{
		Credentials: out.Credentials,
		Region:      provider.AWS.Region,
	}

	json.NewEncoder(w).Encode(result)
}

func (s *server) handleAssumeRole(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	provider, err := s.conf.FindProfile(r.FormValue("profile_id"))
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	creds := s.creds[provider.ID]

	if creds == nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, "No creds available")
		return
	}

	r.ParseForm()
	timeoutSeconds := 60 * 60
	timeoutSecsStr := r.FormValue("timeout_seconds")
	if timeoutSecsStr != "" {
		i, _ := strconv.Atoi(timeoutSecsStr)
		if i > 0 {
			timeoutSeconds = i
		}
	}

	err = s.confirmUserPresence(r.Context())
	if err != nil {
		w.WriteHeader(400)
		fmt.Fprintf(w, err.Error())
		return
	}

	if creds.Expiration.Before(time.Now()) {
		w.WriteHeader(400)
		fmt.Fprintf(w, "creds expired: %s", creds.Expiration)
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(provider.AWS.Region),
		Credentials: credentials.NewStaticCredentials(*creds.AccessKeyId, *creds.SecretAccessKey, *creds.SessionToken),
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

	roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", provider.AWS.Partition, accountID, roleName)

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

	result := messages.Credentials{
		Credentials: out.Credentials,
		Region:      provider.AWS.Region,
	}

	json.NewEncoder(w).Encode(result)
}

func awsTOTP(ctx context.Context, oathName string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ykman", "oath", "code", oathName, "-s").CombinedOutput()

	out = bytes.TrimSpace(out)

	return string(out), err
}
