// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package tlsutils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"
)

type SelfSignedCA struct {
	privateKey       *rsa.PrivateKey
	certificateBytes []byte
	ca               *x509.Certificate
}

func NewSelfSignedCA(subject pkix.Name, validTo time.Time) (*SelfSignedCA, error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixMicro()),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              validTo,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %v", err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return &SelfSignedCA{
		privateKey:       caPrivKey,
		ca:               ca,
		certificateBytes: caBytes,
	}, nil
}

func NewCAFromFiles(keyPath, certPath string) (*SelfSignedCA, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyPem, _ := pem.Decode(keyBytes)
	if keyPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid key type: %s", keyPem.Type)
	}
	if keyPem == nil {
		return nil, fmt.Errorf("invalid key pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, err
	}

	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		return nil, fmt.Errorf("invalid cert pem")
	}
	if certPem.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid cert type: %s", certPem.Type)
	}
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	return &SelfSignedCA{
		privateKey:       key,
		ca:               cert,
		certificateBytes: certPem.Bytes,
	}, nil
}

func (ca *SelfSignedCA) CACertBytes() []byte {
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certificateBytes,
	})

	return caPEM.Bytes()
}

func (ca *SelfSignedCA) CAKeyBytes() []byte {
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.privateKey),
	})

	return caPrivKeyPEM.Bytes()
}

func (ca *SelfSignedCA) CreateAndSignCertificate(cert *x509.Certificate) (certPEMBytes, keyPEMBytes []byte, err error) {
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key: %v", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.ca, &certPrivKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}
