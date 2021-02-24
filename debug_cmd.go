package main

import (
	"context"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func debugCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug Commands",
	}

	cmd.AddCommand(u2fVerifyCommand())

	return cmd
}

func u2fVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "u2f-verify",
		Short: "verify a u2f device",
		Run:   u2fVerifyAction,
	}
}

func u2fVerifyAction(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	err := verifyDevice(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ok!\n")
}
