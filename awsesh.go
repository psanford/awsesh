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

func main() {
	if os.Getenv("AWS_DEFAULT_REGION") != "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	rootCmd.AddCommand(u2fRegisterCommand())
	rootCmd.AddCommand(u2fVerifyCommand())
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

func u2fVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "u2f-verify",
		Short: "verify a u2f device",
		Run:   u2fVerifyAction,
	}
}

func u2fVerifyAction(cmd *cobra.Command, args []string) {
	err := verifyDevice()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ok!\n")
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
