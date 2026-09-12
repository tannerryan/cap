// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SignatureOptions sets the certificate checks used by VerifySignature.
type SignatureOptions struct {
	// Roots contains trusted certificate authorities. Nil uses system roots.
	Roots *x509.CertPool
	// CurrentTime is the certificate verification time. Zero uses time.Now.
	CurrentTime time.Time
	// KeyUsages limits accepted certificate uses. Empty accepts any use.
	KeyUsages []x509.ExtKeyUsage
	// CertificateCheck runs after the certificate chain is checked.
	CertificateCheck func(*x509.Certificate, [][]*x509.Certificate) error
}

// SignatureCertificates returns the certificates in the first XML signature.
// The returned certificates have not been checked for trust.
func SignatureCertificates(data []byte) ([]*x509.Certificate, error) {
	if err := checkCAPNamespaces(data); err != nil {
		return nil, err
	}
	var document struct {
		Signature []struct {
			Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	}
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if len(document.Signature) == 0 {
		return nil, errors.New("cap: XML signature is missing")
	}
	certificates := make([]*x509.Certificate, len(document.Signature[0].Certificates))
	for i, encoded := range document.Signature[0].Certificates {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
		if err != nil {
			return nil, fmt.Errorf("cap: decode signature certificate %d: %w", i, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cap: parse signature certificate %d: %w", i, err)
		}
		certificates[i] = certificate
	}
	if len(certificates) == 0 {
		return nil, errors.New("cap: signature certificate is missing")
	}
	return certificates, nil
}

// VerifySignature verifies the first enveloped XML signature and its signer
// certificate. When Roots is nil, the system certificate pool is used.
func VerifySignature(data []byte, options SignatureOptions) (*x509.Certificate, error) {
	certificates, err := SignatureCertificates(data)
	if err != nil {
		return nil, err
	}
	leaf := certificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	currentTime := options.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	keyUsages := options.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         options.Roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     keyUsages,
	})
	if err != nil {
		return nil, fmt.Errorf("cap: verify signature certificate: %w", err)
	}
	if options.CertificateCheck != nil {
		if err := options.CertificateCheck(leaf, chains); err != nil {
			return nil, fmt.Errorf("cap: signature certificate rejected: %w", err)
		}
	}

	document := etree.NewDocument()
	if err := document.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("cap: parse signed XML: %w", err)
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{leaf}}
	context := dsig.NewDefaultValidationContext(store)
	context.Clock = dsig.NewFakeClockAt(currentTime)
	if _, err := context.Validate(document.Root()); err != nil {
		return nil, fmt.Errorf("cap: verify XML signature: %w", err)
	}
	return leaf, nil
}
