package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/route53"
	"github.com/go-acme/lego/v5/registration"
)

// loosely following https://go-acme.github.io/lego/library/index.html
// to try to make a Go ACME client

type AccountMetadata struct {
	Email            string `json:"email"`
	ACMEDirectoryURL string `json:"ACMEDirectoryURL"`
}

type Account struct {
	AccountMetadata
	Registration *acme.ExtendedAccount `json:"registration"`
	Key          *rsa.PrivateKey       `json:"key"`

	store  Store
	client *lego.Client
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetRegistration() *acme.ExtendedAccount {
	return a.Registration
}

func (a *Account) GetPrivateKey() crypto.Signer {
	return a.Key
}

type Store interface {
	LoadAccount(meta AccountMetadata) (*Account, error)
	SaveAccount(*Account) error
	LoadCert(domain string) (*Certificate, error)
	SaveCert(cert *Certificate) error
}

var (
	ErrAccountDoesNotExist     = errors.New("account does not exist")
	ErrAccountUninitialized    = errors.New("account has not been initialized")
	ErrCertificateDoesNotExist = errors.New("certificate does not exist")
)

func GetAccount(meta AccountMetadata, store Store) (*Account, error) {
	account, err := store.LoadAccount(meta)
	if errors.Is(err, ErrAccountDoesNotExist) {
		return newAccount(meta, store)
	}
	if err != nil {
		return nil, err
	}

	err = account.initClient()
	if err != nil {
		return nil, err
	}
	account.Registration, err = account.client.Registration.QueryRegistration(context.Background())
	if err != nil {
		return nil, fmt.Errorf("querying registration: %w", err)
	}
	account.store = store

	return account, nil
}

func newAccount(meta AccountMetadata, store Store) (*Account, error) {
	privateKey, err := rsa.GenerateKey(nil, 4096)
	if err != nil {
		return nil, err
	}

	account := &Account{
		AccountMetadata: meta,
		Key:             privateKey,
	}

	err = account.initClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// New users will need to register
	reg, err := account.client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register account: %w", err)
	}
	account.Registration = reg
	err = store.SaveAccount(account)
	if err != nil {
		return nil, fmt.Errorf("failed to save account: %w", err)
	}
	return account, nil
}

func (a *Account) initClient() error {
	config := lego.NewConfig(a)
	config.CADirURL = a.ACMEDirectoryURL
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("error creating lego client: %w", err)
	}

	var prov challenge.Provider
	switch a.ACMEDirectoryURL {
	case lego.DirectoryURLLetsEncrypt, lego.DirectoryURLLetsEncryptStaging:
		prov, err = route53.NewDNSProvider()
	default:
		return fmt.Errorf("unsupported directory URL: %s", a.ACMEDirectoryURL)
	}
	if err != nil {
		return err
	}

	err = client.Challenge.SetDNS01Provider(prov)
	if err != nil {
		return fmt.Errorf("failed to set DNS provider challenge: %w", err)
	}

	a.client = client
	return nil
}

type Certificate struct {
	Domain      string `json:"domain"`
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
}

func (a *Account) Request(ctx context.Context, domain string) (*Certificate, error) {
	if a.client == nil {
		return nil, ErrAccountUninitialized
	}

	cert, err := a.store.LoadCert(domain)
	if err == nil {
		return cert, nil
	}
	if !errors.Is(err, ErrCertificateDoesNotExist) {
		return nil, err
	}

	resource, err := a.client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: []string{domain, fmt.Sprintf("*.%s", domain)},
		KeyType: certcrypto.RSA4096,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtaining certificate for domain %s: %w", domain, err)
	}

	err = a.store.SaveAccount(a)
	if err != nil {
		log.Printf("failed to save account: %v", err)
	}

	cert = &Certificate{
		Domain:      domain,
		PrivateKey:  string(resource.PrivateKey),
		Certificate: string(resource.Certificate),
	}

	err = a.store.SaveCert(cert)
	if err != nil {
		return nil, fmt.Errorf("saving certificate for domain %s: %w", domain, err)
	}

	return cert, nil
}
