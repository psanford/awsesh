package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	KeyHandle string    `toml:"key-handle"`
	TPMPath   string    `toml:"tpm-path"`
	Profile   []Profile `toml:"profile"`
}

type Profile struct {
	ID       string `toml:"id"`
	Provider string `toml:"provider"`
	OP       struct {
		Subdomain string `toml:"subdomain"`
		Vault     string `toml:"vault"`
		Key       string `toml:"key"`
	} `toml:"op"`
	AWS struct {
		MFASerial    string `toml:"mfa-serial"`
		OathName     string `toml:"oath-name"`
		TOTPProvider string `toml:"totp-provider"` // yubikey|tpm|pass

		// AWS Region. If empty string, will default to "us-east-1"
		Region string `toml:"region"`
		// AWS ARN partition. If empty string will default to "aws".
		// Use this for gov and china partitions
		Partition string `toml:"partition"`
	} `toml:"aws"`
	Pass struct {
		Path string `toml:"path"`
	}
}

func (c *Config) FindProfile(id string) (Profile, error) {
	if id == "" {
		return c.Profile[0], nil
	}
	for _, p := range c.Profile {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, errors.New("no profile found matching id")
}

var AWSDefaultRegion = "us-east-1"
var AWSDefaultPartition = "aws"

func confDir() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return filepath.Join(u.HomeDir, ".awsesh")
}

func SocketPath() string {
	sockPath := os.Getenv("AWSESH_SOCKET")
	if sockPath != "" {
		return sockPath
	}
	return filepath.Join(confDir(), ".control.sock")
}

func LoadConfig() Config {
	confPath := filepath.Join(confDir(), "config.toml")
	tml, err := ioutil.ReadFile(confPath)
	if err != nil {
		panic(err)
	}
	var conf Config
	err = toml.Unmarshal(tml, &conf)
	if err != nil {
		panic(err)
	}

	if conf.KeyHandle == "" {
		panic(fmt.Sprintf("key-handle not set in config file"))
	}

	for i, p := range conf.Profile {
		if p.AWS.Region == "" {
			p.AWS.Region = AWSDefaultRegion
		}
		if p.AWS.Partition == "" {
			p.AWS.Partition = AWSDefaultPartition
		}
		if p.AWS.TOTPProvider == "" {
			p.AWS.TOTPProvider = "yubikey"
		}
		if p.AWS.TOTPProvider != "yubikey" && p.AWS.TOTPProvider != "tpm" && p.AWS.TOTPProvider != "pass" {
			panic(fmt.Sprintf("invalid totp-provider: %s, must be 'yubikey', 'tpm', 'pass' or unset", p.AWS.TOTPProvider))
		}
		conf.Profile[i] = p
	}

	return conf
}

type Account struct {
	Env  string
	ID   string
	Role string
	Name string
}

func (a Account) String() string {
	return fmt.Sprintf("%s-%s-%s", a.Env, a.Name, a.ID)
}

func ValidAccounts() []Account {
	path := filepath.Join(confDir(), "accounts")

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Account

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 3 {
			continue
		}
		out = append(out, Account{
			Env:  parts[0],
			ID:   parts[1],
			Role: parts[2],
			Name: parts[3],
		})
	}
	return out
}
