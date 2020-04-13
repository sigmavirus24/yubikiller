package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sigmavirus24/yubikiller"
)

func main() {
	flags := flag.NewFlagSet("yubikiller", flag.ExitOnError)
	flags.Parse(os.Args[1:])

	if flags.NArg() != 1 {
		fmt.Println("requires at least 1 yubikey OTP to invalidate")
		os.Exit(2)
	}
	otp := flags.Arg(0)
	if err := yubikiller.InvalidateToken(context.Background(), otp); err != nil {
		fmt.Printf("encountered error invalidating token: %q\n", err)
		os.Exit(2)
	}
	fmt.Println("successfully invalidated token")
}
