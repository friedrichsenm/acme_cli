package main

import (
	"acme-client/client"
	"acme-client/store"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	email := flag.String("email", "", "email address")
	ACMEDir := flag.String("acme-dir", "https://acme-staging-v02.api.letsencrypt.org/directory", "acme dir")
	folder := flag.String("folder", ".certs", "folder name to store account data")
	domain := flag.String("domain", "", "domain name")

	flag.Parse()
	if *email == "" || *folder == "" || *ACMEDir == "" || *domain == "" {
		flag.PrintDefaults()
		log.Fatal("missing arguments")
	}

	if os.Getenv("AWS_PROFILE") == "" {
		log.Fatal("AWS_PROFILE environment variable not set")
	}

	filestore, err := store.NewFileStore(*folder)
	if err != nil {
		log.Fatal(err)
	}

	account, err := client.GetAccount(client.AccountMetadata{
		Email:            *email,
		ACMEDirectoryURL: *ACMEDir,
	}, filestore)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := account.Request(context.Background(), *domain)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", cert)
	os.Exit(0)
}
