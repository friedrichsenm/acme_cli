package main

import (
	"acme-client/client"
	"acme-client/store"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	email := flag.String("email", "", "email address")
	ACMEDir := flag.String("acme-dir", "https://acme-staging-v02.api.letsencrypt.org/directory", "acme dir")
	folder := flag.String("folder", ".certs", "folder name to store account data")

	flag.Parse()
	if *email == "" || *folder == "" || *ACMEDir == "" {
		flag.PrintDefaults()
		log.Fatal("missing arguments")
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

	fmt.Println(account)
	os.Exit(0)
}
