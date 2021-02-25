package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

var region = "us-east-1"

var rootCmd = &cobra.Command{
	Use:   "awsesh",
	Short: "AWS Session Helpers",
}

var conf Config

func main() {
	conf = loadConfig()

	if os.Getenv("AWS_DEFAULT_REGION") != "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	rootCmd.AddCommand(u2fRegisterCommand())
	rootCmd.AddCommand(debugCommand())
	rootCmd.AddCommand(listAccountsCommand())
	rootCmd.AddCommand(loginCommand())
	rootCmd.AddCommand(assumeRoleCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(sessionCommand())
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
	s := newServer()
	err := s.listenAndServe()
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
	handle, err := registerDevice()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key-handle: %s\n", handle.MarshalKey())
}

func loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "login command",
		Run:   loginAction,
	}
}

func loginAction(cmd *cobra.Command, args []string) {
	client := NewClient()

	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	err = client.Login()
	if err != nil {
		log.Fatalf("Login error: %s", err)
	}

	log.Println("ok")
}

var (
	accountIDF   string
	roleNameF    string
	accountNameF string
	printEnv     bool
)

func assumeRoleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assume",
		Short: "assume role",
		Run:   assumeRoleAction,
	}

	cmd.Flags().StringVarP(&accountIDF, "account-id", "", "", "Account ID")
	cmd.Flags().StringVarP(&roleNameF, "role", "", "", "Role Name")
	cmd.Flags().StringVarP(&accountNameF, "name", "", "", "Account Name (friendly)")
	cmd.Flags().BoolVarP(&printEnv, "print", "", false, "Print ENV settings")

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
		for _, acct := range validAccounts() {
			if given == acct.String() || given == acct.id {
				accountID = acct.id
				accountName = acct.env + "-" + acct.name
				roleName = acct.role
				break
			}
		}
	} else {
		log.Fatalf("usage: assume <account_id|long-account-id> [--account-id <id>, --role <role>, --name <friendly-name>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	client := NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	creds, err := client.AssumeRole(accountID, roleName, accountName)
	if err != nil {
		log.Fatal(err)
	}

	if accountName == "" {
		accountName = fmt.Sprintf("%s-%s", accountID, roleName)
	}

	startEnvOrPrint(creds, accountName)
}
func startEnvOrPrint(creds *sts.Credentials, name string) {
	if printEnv {
		fmt.Printf("  export AWS_ACCESS_KEY_ID=%s\n", *creds.AccessKeyId)
		fmt.Printf("  export AWS_SECRET_ACCESS_KEY=%s\n", *creds.SecretAccessKey)
		fmt.Printf("  export AWS_SESSION_TOKEN=%s\n", *creds.SessionToken)
		fmt.Printf("  export AWSESH_PROFILE=\"%s\"", name)
		fmt.Printf(`  export PS1="(awsesh-%s)  \\[\\033[01;35m\\]\\w\\[\\033[00m\\]\\$ "`, name)
		fmt.Println()
	} else {
		env := environ(os.Environ())
		env.Set("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
		env.Set("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
		env.Set("AWS_SESSION_TOKEN", *creds.SessionToken)
		env.Set("AWSESH_PROFILE", name)

		cmd := exec.Command("/bin/bash")
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
	accounts := validAccounts()

	var completions []string
	for _, account := range accounts {
		if strings.HasPrefix(account.String(), toComplete) {
			completions = append(completions, account.String())
		}
		if strings.HasPrefix(account.id, toComplete) {
			completions = append(completions, account.id)
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

	return cmd
}

func sessionAction(cmd *cobra.Command, args []string) {
	client := NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	creds, err := client.Session()
	if err != nil {
		log.Fatal(err)
	}

	startEnvOrPrint(creds, "mommy-session")
}

func mommySession() *awssession.Session {
	sess, err := awssession.NewSession(&aws.Config{Region: &region})
	if err != nil {
		log.Fatalf("AWS NewSession error: %s", err)
	}

	return sess
}

func listAccountsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list-accounts",
		Short: "list-accounts",
		Run:   listAccountsAction,
	}
}

func listAccountsAction(cmd *cobra.Command, args []string) {
	for _, acct := range validAccounts() {
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
