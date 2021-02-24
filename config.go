package main

import (
	"fmt"
	"io/ioutil"
	"os/user"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	KeyHandle string `toml:"key-handle"`
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
	fmt.Printf("path: %s\n", confPath)
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
