// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	validFor = 365 * 24 * time.Hour
)

func publicKey(priv interface{}) (answer interface{}) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		answer = &k.PublicKey
	case *ecdsa.PrivateKey:
		answer = &k.PublicKey
	}
	return
}

func pemBlockForKey(priv interface{}) (answer *pem.Block, err error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		answer = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		if b, err2 := x509.MarshalECPrivateKey(k); err2 != nil {
			err = fmt.Errorf("Unable to marshal ECDSA private key: %v", err2)
		} else {
			answer = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
		}
	}
	return
}

func buildKeys(curveOrBits, certFile, keyFile string) error {
	ips, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	addrs := []string{"greg.fill.in", "localhost"}
	for _, ip := range ips {
		cidr := ip.String()
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil || ip == nil {
			continue
		}
		addrs = append(addrs, ip.String())
	}

	rsaBits := 2048
	var ecdsaCurve string
	if curveOrBits[0] == 'P' {
		ecdsaCurve = curveOrBits
	} else if curveOrBits == "RSA" {
		ecdsaCurve = "RSA"
	} else {
		ecdsaCurve = "RSA"
		rsaBits, err = strconv.Atoi(curveOrBits)
		if err != nil {
			return err
		}
	}

	var priv interface{}
	switch ecdsaCurve {
	case "RSA":
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("Unrecognized elliptic curve: %q", ecdsaCurve)
	}
	if err != nil {
		return fmt.Errorf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range addrs {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %s", err)
	}

	b, err := pemBlockForKey(priv)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, b)
	keyOut.Close()
	return nil
}
