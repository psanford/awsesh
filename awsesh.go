package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
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
	rootCmd.AddCommand(loginCommand())
	rootCmd.AddCommand(assumeRoleCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(sessionCommand())

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

	log.Printf("Prepare to tap yubikey...")

	err = client.Login()
	if err != nil {
		log.Fatalf("Login error: %s", err)
	}

	log.Println("ok")
}

func assumeRoleCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "assume",
		Short: "assume role",
		Run:   assumeRoleAction,
	}
}

func assumeRoleAction(cmd *cobra.Command, args []string) {
	if len(args) != 2 {
		log.Fatalf("usage: assume <account_id> <role_name")
	}

	client := NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	err = client.AssumeRole(args[0], args[1])
	if err != nil {
		log.Fatal(err)
	}
}

func sessionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "session",
		Short: "create a session",
		Run:   sessionAction,
	}
}

func sessionAction(cmd *cobra.Command, args []string) {

}

func mommySession() *awssession.Session {
	sess, err := awssession.NewSession(&aws.Config{Region: &region})
	if err != nil {
		log.Fatalf("AWS NewSession error: %s", err)
	}

	return sess
}
