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

	fmt.Println("write")
	stdin.Write([]byte(passwd))
	stdin.Close()

	fmt.Println("wait")
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

	cmd := exec.Command(opPath, "get", "item", "--vault", op.vault, op.item)
	cmd.Env = append(os.Environ(), fmt.Sprintf("OP_SESSION_%s=%s", op.subdomain, op.sessionToken))

	rawOut, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	var obj opObject
	err = json.Unmarshal(rawOut, &obj)
	if err != nil {
		return nil, err
	}

	var creds passprovider.AwsCreds
	for _, f := range obj.Details.Fields {
		switch f.Name {
		case "username":
			creds.AccessKeyID = f.Value
		case "password":
			creds.SecretAccessKey = f.Value
		}
	}

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("Failed to find creds in 1password")
	}

	return &creds, nil
}

type opObject struct {
	ChangerUUID string `json:"changerUuid"`
	CreatedAt   string `json:"createdAt"`
	Details     struct {
		Fields []struct {
			Designation string `json:"designation"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Value       string `json:"value"`
		} `json:"fields"`
		NotesPlain string        `json:"notesPlain"`
		Sections   []interface{} `json:"sections"`
	} `json:"details"`
	ItemVersion int64 `json:"itemVersion"`
	Overview    struct {
		URLs  []interface{} `json:"URLs"`
		Ainfo string        `json:"ainfo"`
		Ps    int64         `json:"ps"`
		Tags  []interface{} `json:"tags"`
		Title string        `json:"title"`
		URL   string        `json:"url"`
	} `json:"overview"`
	TemplateUUID string `json:"templateUuid"`
	Trashed      string `json:"trashed"`
	UpdatedAt    string `json:"updatedAt"`
	UUID         string `json:"uuid"`
	VaultUUID    string `json:"vaultUuid"`
}
