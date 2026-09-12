// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/tannerryan/cap"
)

// TestVerifySignature checks XML and certificate verification.
func TestVerifySignature(t *testing.T) {
	data, trusted, signedAt := signedAlert(t)
	certificates, err := cap.SignatureCertificates(data)
	if err != nil {
		t.Fatal(err)
	}
	alert, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(alert.Signature) != 1 || len(alert.Signature[0].X509Certificate) != 1 {
		t.Fatalf("signature = %#v", alert.Signature)
	}
	roots := x509.NewCertPool()
	roots.AddCert(trusted)
	certificate, err := cap.VerifySignature(data, cap.SignatureOptions{
		Roots:       roots,
		CurrentTime: signedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.Equal(certificates[0]) {
		t.Fatal("verified certificate does not match embedded certificate")
	}
	if _, err := cap.VerifySignature(data, cap.SignatureOptions{
		Roots:       roots,
		CurrentTime: signedAt,
		CertificateCheck: func(*x509.Certificate, [][]*x509.Certificate) error {
			return errors.New("rejected for test")
		},
	}); err == nil {
		t.Fatal("expected certificate check rejection")
	}
}

// TestVerifySignatureRejectsChangedMessage checks tamper detection.
func TestVerifySignatureRejectsChangedMessage(t *testing.T) {
	data, trusted, signedAt := signedAlert(t)
	roots := x509.NewCertPool()
	roots.AddCert(trusted)
	data = []byte(strings.Replace(string(data), "Test event", "Changed event", 1))
	if _, err := cap.VerifySignature(data, cap.SignatureOptions{
		Roots:       roots,
		CurrentTime: signedAt,
	}); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

// TestSignatureCertificatesRejectsNonCAPRoot checks root validation.
func TestSignatureCertificatesRejectsNonCAPRoot(t *testing.T) {
	data, _, _ := signedAlert(t)
	data = []byte(strings.Replace(string(data), "<alert", "<message", 1))
	data = []byte(strings.Replace(string(data), "</alert>", "</message>", 1))
	if _, err := cap.SignatureCertificates(data); err == nil {
		t.Fatal("expected non-CAP root error")
	}
}

// TestParseMultipleSignatures checks repeated signature elements.
func TestParseMultipleSignatures(t *testing.T) {
	data, err := os.ReadFile("testing/PelmorexNAADS_WindWarning.xml")
	if err != nil {
		t.Fatal(err)
	}
	alert, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(alert.Signature) != 2 || len(alert.Signature[0].SignatureProperties) != 2 {
		t.Fatalf("signatures = %#v", alert.Signature)
	}
}

// signedAlert creates a trusted signed alert for verification tests.
func signedAlert(t *testing.T) ([]byte, *x509.Certificate, time.Time) {
	t.Helper()
	unsigned, err := cap.MarshalCAP(validAlert(t))
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(unsigned); err != nil {
		t.Fatal(err)
	}
	keyStore := dsig.RandomKeyStoreForTest()
	context := dsig.NewDefaultSigningContext(keyStore)
	signed, err := context.SignEnveloped(document.Root())
	if err != nil {
		t.Fatal(err)
	}
	document.SetRoot(signed)
	data, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	_, der, err := keyStore.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return data, certificate, certificate.NotBefore.Add(time.Minute)
}
