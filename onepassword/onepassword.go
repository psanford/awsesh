package onepassword

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/psanford/awsesh/passprovider"
	"github.com/psanford/awsesh/pinentry"
)

func New(subdomain, vault, item string) passprovider.Provider {
	return &onepass{
		subdomain: subdomain,
		vault:     vault,
		item:      item,
	}
}

type onepass struct {
	subdomain string
	vault     string
	item      string

	sessionToken string
}

func (op *onepass) login() error {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return fmt.Errorf("failed to find 'op' binary: %w", err)
	}

	passwd, err := pinentry.GetPin("Enter your master 1password:")
	if err != nil {
		return fmt.Errorf("failed to get password from user: %w", err)
	}

	cmd := exec.Command(opPath, "signin", "--raw")
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	stdin.Write([]byte(passwd))
	stdin.Close()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("failed to login to 1password: %s", stderr.Bytes())
	}
	sessionID := bytes.TrimSpace(stdout.Bytes())

	op.sessionToken = string(sessionID)

	return nil
}

func (op *onepass) AWSCreds() (*passprovider.AwsCreds, error) {
	err := op.login()
	if err != nil {
		return nil, err
	}

	opPath, err := exec.LookPath("op")
	if err != nil {
		return nil, fmt.Errorf("failed to find 'op' binary: %w", err)
	}

	cmd := exec.Command(opPath, "item", "get", "--format", "json", "--vault", op.vault, op.item)
	cmd.Env = append(os.Environ(), fmt.Sprintf("OP_SESSION_%s=%s", op.subdomain, op.sessionToken))

	rawOut, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("op item get err: %w, %s", err, rawOut)
	}

	var obj opObject
	err = json.Unmarshal(rawOut, &obj)
	if err != nil {
		return nil, err
	}

	var creds passprovider.AwsCreds
	for _, f := range obj.Fields {
		switch f.ID {
		case "username":
			creds.AccessKeyID = f.Value
		case "password":
			if len(f.Value) < 100 {
				creds.SecretAccessKey = f.Value
			} else {
				creds.TPMHandle = f.Value
			}
		}
	}

	if creds.AccessKeyID == "" || (creds.SecretAccessKey == "" && creds.TPMHandle == "") {
		return nil, fmt.Errorf("Failed to find creds in 1password")
	}

	return &creds, nil
}

type opObject struct {
	AdditionalInformation string `json:"additional_information"`
	Category              string `json:"category"`
	CreatedAt             string `json:"created_at"`
	Fields                []struct {
		ID              string `json:"id"`
		Label           string `json:"label"`
		PasswordDetails struct {
			Strength string `json:"strength"`
		} `json:"password_details"`
		Purpose   string `json:"purpose"`
		Reference string `json:"reference"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"fields"`
	ID           string `json:"id"`
	LastEditedBy string `json:"last_edited_by"`
	Title        string `json:"title"`
	UpdatedAt    string `json:"updated_at"`
	Vault        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	Version int64 `json:"version"`
}
