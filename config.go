package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	KeyHandle string `toml:"key-handle"`
	OP        struct {
		Subdomain string `toml:"subdomain"`
		Vault     string `toml:"vault"`
		Key       string `toml:"key"`
	} `toml:"op"`
	AWS struct {
		MFASerial string `toml:"mfa-serial"`
	} `toml:"aws"`
}

func confDir() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return filepath.Join(u.HomeDir, ".awsesh")
}

func socketPath() string {
	return filepath.Join(confDir(), ".control.sock")
}

func loadConfig() Config {
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

type account struct {
	env  string
	id   string
	role string
	name string
}

func (a account) String() string {
	return fmt.Sprintf("%s-%s-%s", a.env, a.name, a.id)
}

func validAccounts() []account {
	path := filepath.Join(confDir(), "accounts")

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []account

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
		out = append(out, account{
			env:  parts[0],
			id:   parts[1],
			role: parts[2],
			name: parts[3],
		})
	}
	return out
}
