package pass

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"

	"github.com/psanford/awsesh/passprovider"
)

func New(path string) passprovider.Provider {
	return &pass{
		path: path,
	}
}

type pass struct {
	path string
}

func (p *pass) AWSCreds() (*passprovider.AwsCreds, error) {
	cmd := exec.Command("pass", p.path)

	rawOut, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var wrapper VaultCredWrapper
	err = json.Unmarshal(rawOut, &wrapper)
	if err != nil {
		return nil, err
	}

	var innerJSON []byte
	if wrapper.Data != "" {
		innerJSON, err = base64.StdEncoding.DecodeString(wrapper.Data)
		if err != nil {
			return nil, err
		}
	} else {
		innerJSON = rawOut
	}

	var vaultCred VaultCred
	json.Unmarshal([]byte(innerJSON), &vaultCred)
	if err != nil {
		return nil, err
	}

	out := passprovider.AwsCreds{
		AccessKeyID:     vaultCred.AccessKeyID,
		SecretAccessKey: vaultCred.SecretAccessKey,
		TPMHandle:       vaultCred.TPMHandle,
	}

	return &out, nil
}

type VaultCredWrapper struct {
	Key  string `json:"key"`
	Data string `json:"data"`
}

type VaultCred struct {
	AccessKeyID     string `json:"AccessKeyID"`
	SecretAccessKey string `json:"SecretAccessKey"`
	TPMHandle       string `json:"secret-access-key-tpm-handle"`
}
