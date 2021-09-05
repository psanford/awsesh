package tpmcli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/psanford/awsesh/tpm"
)

func MakeKeyHandle(tpmPath string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Your SecretAccessKey: ")
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("Error reading from stdin: %s\n", err)
	}
	secretAccessKey := strings.TrimSpace(line)

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return "", fmt.Errorf("Open tpm err: %w", err)
	}
	defer rwc.Close()

	allHandles := []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient, tpm2.HandleTypeHMACSession}

	for _, handleType := range allHandles {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			return "", fmt.Errorf("get handle err: %w", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return "", fmt.Errorf("flush handle err: %w", err)
			}
		}
	}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, emptyPassword, emptyPassword, tpm.PrimaryKeyParams)
	if err != nil {
		return "", fmt.Errorf("CreatePrimary err: %w", err)
	}
	defer tpm2.FlushContext(rwc, pkh)

	public := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		AuthPolicy: []byte(defaultPassword),
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:  tpm2.AlgHMAC,
			Hash: tpm2.AlgSHA256,
		},
	}
	hmacKeyBytes := []byte("AWS4" + secretAccessKey)
	privInternal, pubArea, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, pkh, tpm2.PCRSelection{}, defaultPassword, defaultPassword, public, hmacKeyBytes)
	if err != nil {
		return "", fmt.Errorf("CreateKeyWithSensitive err: %w", err)
	}

	k := tpm.Key{
		Pub:  pubArea,
		Priv: privInternal,
	}

	jk, err := json.Marshal(k)
	if err != nil {
		return "", fmt.Errorf("marshal json err: %w", err)
	}

	// This double base64 encodes most of this payload, which is silly. I still think this is better than
	// having json in json from a usability perspective.
	return base64.URLEncoding.EncodeToString(jk), nil
}

const (
	emptyPassword                   = ""
	defaultPassword                 = ""
	CmdHmacStart    tpmutil.Command = 0x0000015B
)
