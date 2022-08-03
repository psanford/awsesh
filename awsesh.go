package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/psanford/awsesh/client"
	"github.com/psanford/awsesh/config"
	"github.com/psanford/awsesh/internal/tpm"
	"github.com/psanford/awsesh/messages"
	"github.com/psanford/awsesh/server"
	"github.com/psanford/awsesh/u2f"
	"github.com/spf13/cobra"
)

var (
	profileID string

	rootCmd = &cobra.Command{
		Use:   "awsesh",
		Short: "AWS Session Helpers",
	}
	region = "us-east-1"
)

func main() {
	if os.Getenv("AWS_DEFAULT_REGION") != "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	profileID = os.Getenv("AWSESH_PROFILE_ID")

	rootCmd.PersistentFlags().StringVarP(&profileID, "profile", "p", "", "Profile ID to use (defaults to first in config file)")

	rootCmd.AddCommand(u2fRegisterCommand())
	rootCmd.AddCommand(tpmMakeKeyHandleCommand())
	rootCmd.AddCommand(debugCommand())
	rootCmd.AddCommand(listAccountsCommand())
	rootCmd.AddCommand(loginCommand())
	rootCmd.AddCommand(assumeRoleCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(sessionCommand())
	rootCmd.AddCommand(webCommand())
	rootCmd.AddCommand(completionCommand())

	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func serverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "create a server",
		Run:   serverAction,
	}
}

func serverAction(cmd *cobra.Command, args []string) {
	conf := config.LoadConfig()
	s := server.New(&conf)
	err := s.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}

}

func u2fRegisterCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "u2f-register",
		Short: "register a u2f device",
		Run:   u2fRegisterAction,
	}
}

func u2fRegisterAction(cmd *cobra.Command, args []string) {
	handle, err := u2f.RegisterDevice()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key-handle:\n%s\n", handle.MarshalKey())
}

func tpmMakeKeyHandleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tpm-make-encrypted-key",
		Short: "make an encrypte tpm key for SecretAccessKey",
		Run:   tpmMakeKeyHandleAction,
	}

	cmd.Flags().StringVarP(&tpmPath, "tpm-path", "", "/dev/tpmrm0", "TPM Path")

	return cmd
}

func tpmMakeKeyHandleAction(cmd *cobra.Command, args []string) {
	handleStr, err := tpm.MakeKeyHandle(tpmPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tpm-encrypted-key: %s\n", handleStr)
}

func loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "login command",
		Run:   loginAction,
	}
}

func loginAction(cmd *cobra.Command, args []string) {
	client := client.NewClient()

	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	err = client.Login(profileID)
	if err != nil {
		log.Fatalf("Login error: %s", err)
	}

	log.Println("ok")
}

var (
	accountIDF            string
	roleNameF             string
	fromEnvF              bool
	accountNameF          string
	execCmd               string
	printEnv              bool
	timeoutMinutesRole    int
	timeoutMinutesSession int
	tpmPath               string
)

func assumeRoleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "assume-role",
		Aliases: []string{"assume"},
		Short:   "assume role",
		Run:     assumeRoleAction,
	}

	cmd.Flags().StringVarP(&accountIDF, "account-id", "", "", "Account ID")
	cmd.Flags().StringVarP(&roleNameF, "role", "", "", "Role Name")
	cmd.Flags().StringVarP(&accountNameF, "name", "", "", "Account Name (friendly)")
	cmd.Flags().BoolVarP(&printEnv, "print", "", false, "Print ENV settings")
	cmd.Flags().StringVarP(&execCmd, "exec", "", "", "Exec command instead of dropping to shell")
	cmd.Flags().IntVarP(&timeoutMinutesRole, "timeout-minutes", "", 60, "Timeout in minutes")

	cmd.ValidArgsFunction = assumeRoleCompletions

	return cmd
}

func assumeRoleAction(cmd *cobra.Command, args []string) {
	var (
		accountID   string
		roleName    string
		accountName string
	)

	if accountIDF != "" && roleNameF != "" {
		accountID = accountIDF
		roleName = roleNameF
		accountName = accountNameF
	} else if len(args) == 1 {
		given := args[0]
		for _, acct := range config.ValidAccounts() {
			if given == acct.String() || given == acct.ID {
				accountID = acct.ID
				accountName = acct.Env + "-" + acct.Name
				roleName = acct.Role
				break
			}
		}
	} else {
		log.Fatalf("usage: assume <account_id|long-account-id> [--account-id <id>, --role <role>, --name <friendly-name>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	creds, err := client.AssumeRole(profileID, accountID, roleName, accountName, timeoutMinutesRole*60)
	if err != nil {
		log.Fatal(err)
	}

	if accountName == "" {
		accountName = fmt.Sprintf("%s-%s", accountID, roleName)
	}

	startEnvOrPrint(creds, accountName)
}

func webCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "web-assume-role",
		Aliases: []string{"web"},
		Short:   "assume role into AWS web console UI",
		Run:     webAction,
	}

	cmd.Flags().StringVarP(&accountIDF, "account-id", "", "", "Account ID")
	cmd.Flags().StringVarP(&roleNameF, "role", "", "", "Role Name")
	cmd.Flags().BoolVarP(&fromEnvF, "from-env", "", false, "Use loaded creds in env")
	cmd.Flags().IntVarP(&timeoutMinutesRole, "timeout-minutes", "", 60, "Timeout in minutes")

	cmd.ValidArgsFunction = assumeRoleCompletions

	return cmd
}

func webAction(cmd *cobra.Command, args []string) {
	var (
		accountID   string
		roleName    string
		accountName string
	)

	if fromEnvF {
		webLoginFromEnv(cmd, args)
		return
	}

	if accountIDF != "" && roleNameF != "" {
		accountID = accountIDF
		roleName = roleNameF
		accountName = accountNameF
	} else if len(args) == 1 {
		given := args[0]
		for _, acct := range config.ValidAccounts() {
			if given == acct.String() || given == acct.ID {
				accountID = acct.ID
				accountName = acct.Env + "-" + acct.Name
				roleName = acct.Role
				break
			}
		}
	} else {
		log.Fatalf("usage: web-assume=role <account_id|long-account-id> [--account-id <id>, --role <role>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	creds, err := client.AssumeRole(profileID, accountID, roleName, accountName, timeoutMinutesRole*60)
	if err != nil {
		log.Fatal(err)
	}

	if accountName == "" {
		accountName = fmt.Sprintf("%s-%s", accountID, roleName)
	}

	jsonTxt, err := json.Marshal(map[string]string{
		"sessionId":    *creds.AccessKeyId,
		"sessionKey":   *creds.SecretAccessKey,
		"sessionToken": *creds.SessionToken,
	})
	if err != nil {
		log.Fatal(err)
	}

	loginURLPrefix := "https://signin.aws.amazon.com/federation"
	req, err := http.NewRequest("GET", loginURLPrefix, nil)
	if err != nil {
		log.Fatal(err)
	}

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonTxt))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("getSigninToken returned non-200 status: %d", resp.StatusCode)
	}

	var signinTokenResp struct {
		SigninToken string `json:"SigninToken"`
	}

	if err = json.Unmarshal([]byte(body), &signinTokenResp); err != nil {
		log.Fatalf("parse signinTokenResp err: %s", err)
	}

	destination := "https://console.aws.amazon.com/"

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		loginURLPrefix,
		url.QueryEscape(destination),
		url.QueryEscape(signinTokenResp.SigninToken),
	)

	fmt.Println(loginURL)
}

func webLoginFromEnv(cmd *cobra.Command, args []string) {
	accessKeyId := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKeyId == "" || secretAccessKey == "" || sessionToken == "" {
		log.Fatalf("ENV variables not set")
	}

	jsonTxt, err := json.Marshal(map[string]string{
		"sessionId":    accessKeyId,
		"sessionKey":   secretAccessKey,
		"sessionToken": sessionToken,
	})
	if err != nil {
		log.Fatal(err)
	}

	loginURLPrefix := "https://signin.aws.amazon.com/federation"
	req, err := http.NewRequest("GET", loginURLPrefix, nil)
	if err != nil {
		log.Fatal(err)
	}

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonTxt))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("getSigninToken returned non-200 status: %d", resp.StatusCode)
	}

	var signinTokenResp struct {
		SigninToken string `json:"SigninToken"`
	}

	if err = json.Unmarshal([]byte(body), &signinTokenResp); err != nil {
		log.Fatalf("parse signinTokenResp err: %s", err)
	}

	destination := "https://console.aws.amazon.com/"

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		loginURLPrefix,
		url.QueryEscape(destination),
		url.QueryEscape(signinTokenResp.SigninToken),
	)

	fmt.Println(loginURL)
}

func startEnvOrPrint(creds *messages.Credentials, name string) {
	if printEnv {
		fmt.Printf("  export AWS_ACCESS_KEY_ID=%s\n", *creds.AccessKeyId)
		fmt.Printf("  export AWS_SECRET_ACCESS_KEY=%s\n", *creds.SecretAccessKey)
		fmt.Printf("  export AWS_SESSION_TOKEN=%s\n", *creds.SessionToken)
		fmt.Printf("  export AWS_DEFAULT_REGION=\"%s\"", creds.Region)
		fmt.Printf("  export AWSESH_PROFILE=\"%s\"", name)
		fmt.Printf("  export AWSESH_SESSION_EXPIRATION=\"%d\"", creds.Expiration.Unix())

		fmt.Printf(`  export PS1="(awsesh-%s)  \\[\\033[01;35m\\]\\w\\[\\033[00m\\]\\$ "`, name)
		fmt.Println()
	} else {
		env := environ(os.Environ())
		env.Set("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
		env.Set("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
		env.Set("AWS_SESSION_TOKEN", *creds.SessionToken)
		env.Set("AWS_DEFAULT_REGION", creds.Region)
		env.Set("AWSESH_PROFILE", name)
		env.Set("AWSESH_SESSION_EXPIRATION", strconv.Itoa(int(creds.Expiration.Unix())))

		var cmd *exec.Cmd
		if execCmd != "" {
			cmd = exec.Command("/bin/sh", "-c", execCmd)
		} else {
			shell := os.Getenv("SHELL")
			if shell == "" {
				shell = "/usr/bin/env bash"
			}
			cmd = exec.Command(shell)
		}
		cmd.Env = env
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		sigs := make(chan os.Signal, 1)

		signal.Notify(sigs, os.Interrupt, os.Kill)

		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- cmd.Wait()
			close(waitCh)
		}()

		for {
			select {
			case sig := <-sigs:
				if err := cmd.Process.Signal(sig); err != nil {
					log.Fatal(err)
					break
				}
			case err := <-waitCh:
				var waitStatus syscall.WaitStatus
				if exitError, ok := err.(*exec.ExitError); ok {
					waitStatus = exitError.Sys().(syscall.WaitStatus)
					os.Exit(waitStatus.ExitStatus())
				}
				if err != nil {
					log.Fatal(err)
				}
				return
			}
		}
	}
}

func assumeRoleCompletions(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	accounts := config.ValidAccounts()

	var completions []string
	for _, account := range accounts {
		if strings.HasPrefix(account.String(), toComplete) {
			completions = append(completions, account.String())
		}
		if strings.HasPrefix(account.ID, toComplete) {
			completions = append(completions, account.ID)
		}
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}

func sessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "create a session",
		Run:   sessionAction,
	}

	cmd.Flags().BoolVarP(&printEnv, "print", "", false, "Print ENV settings")
	cmd.Flags().IntVarP(&timeoutMinutesSession, "timeout-minutes", "", 30, "Session Timeout in minutes")
	cmd.Flags().StringVarP(&execCmd, "exec", "", "", "Exec command instead of dropping to shell")

	return cmd
}

func sessionAction(cmd *cobra.Command, args []string) {
	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	timeoutSeconds := timeoutMinutesSession * 60
	creds, err := client.Session(profileID, timeoutSeconds)
	if err != nil {
		log.Fatal(err)
	}

	startEnvOrPrint(creds, "mommy-session")
}

func listAccountsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list-accounts",
		Short: "list-accounts",
		Run:   listAccountsAction,
	}
}

func listAccountsAction(cmd *cobra.Command, args []string) {
	for _, acct := range config.ValidAccounts() {
		fmt.Println(acct.String())
	}
}

type environ []string

func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}

func completionCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "completion",
		Short: "Generates bash completion scripts",
		Long: `To load completion run

. <(awsesh completion)

To configure your bash shell to load completions for each session add to your bashrc

# ~/.bashrc or ~/.profile
. <(awsesh completion)
`,
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenBashCompletion(os.Stdout)
		},
	}

	return cmd
}
