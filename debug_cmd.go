package main

import (
	"context"
	"fmt"
	"log"

	"github.com/psanford/awsesh/config"
	"github.com/psanford/awsesh/u2f"
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
	conf := config.LoadConfig()
	err := u2f.VerifyDevice(ctx, conf.KeyHandle)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ok!\n")
}
