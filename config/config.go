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
	KeyHandle string     `toml:"key-handle"`
	Provider  []Provider `toml:"provider"`
}

type Provider struct {
	ID   string `toml:"id"`
	Type string `toml:"type"`
	OP   struct {
		Subdomain string `toml:"subdomain"`
		Vault     string `toml:"vault"`
		Key       string `toml:"key"`
	} `toml:"op"`
	AWS struct {
		MFASerial string `toml:"mfa-serial"`
		OathName  string `toml:"oath-name"`
	} `toml:"aws"`
	Pass struct {
		Path string `toml:"path"`
	}
}

func (c *Config) FindProvider(id string) (Provider, error) {
	if id == "" {
		return c.Provider[0], nil
	}
	for _, p := range c.Provider {
		if p.ID == id {
			return p, nil
		}
	}
	return Provider{}, errors.New("no provider found matching id")
}

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
