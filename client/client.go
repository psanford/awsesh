package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/psanford/awsesh/config"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return NewClientWithTimeout(30 * time.Second)
}

func NewClientWithTimeout(tout time.Duration) *Client {
	dialer := net.Dialer{
		Timeout:   tout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", config.SocketPath())
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	return &Client{
		httpClient: httpClient,
	}
}

var fakeHost = "http://example.com"

func (c *Client) Ping() error {
	resp, err := c.httpClient.Get(fakeHost + "/ping")
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Bad response from server: %d\n%s\n", resp.StatusCode, body)
	}

	if string(body) != "pong" {
		return fmt.Errorf("Bad response from server: %d\n%s\n", resp.StatusCode, body)
	}
	return nil
}

func (c *Client) Login() error {
	resp, err := c.httpClient.Get(fakeHost + "/login")
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Bad response from server: %d\n%s\n", resp.StatusCode, body)
	}

	if string(body) != "ok!" {
		return fmt.Errorf("Bad response from server: %d\n%s\n", resp.StatusCode, body)
	}
	return nil
}

func (c *Client) AssumeRole(accountID, roleName, accountName string, timeoutSeconds int) (*sts.Credentials, error) {
	data := make(url.Values)
	data.Set("account_id", accountID)
	data.Set("role_name", roleName)
	data.Set("account_name", accountName)
	if timeoutSeconds > 0 {
		data.Set("timeout_seconds", strconv.Itoa(timeoutSeconds))
	}
	resp, err := c.httpClient.PostForm(fakeHost+"/assume_role", data)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Bad response from server: %d body=<%s>", resp.StatusCode, body)
	}

	var creds sts.Credentials
	err = json.Unmarshal(body, &creds)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal json resp err: %s, body: <%s>", err, body)
	}

	return &creds, nil
}

func (c *Client) Session(timeoutSeconds int) (*sts.Credentials, error) {
	data := make(url.Values)
	if timeoutSeconds > 0 {
		data.Set("timeout_seconds", strconv.Itoa(timeoutSeconds))
	}

	resp, err := c.httpClient.PostForm(fakeHost+"/session", data)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Bad response from server: %d\n%s\n", resp.StatusCode, body)
	}

	var creds sts.Credentials
	err = json.Unmarshal(body, &creds)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal json resp err: %s, body: <%s>", err, body)
	}

	return &creds, nil
}
