// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/tannerryan/cap"
)

// TestMarshalCAPRoundTrip checks XML encoding and optional field presence.
func TestMarshalCAPRoundTrip(t *testing.T) {
	alert := validAlert(t)
	altitude := 0.0
	ceiling := 1000.0
	contents := []byte("resource")
	digest := sha1.Sum(contents)
	size := int64(len(contents))
	alert.Info[0].Area[0].Altitude = &altitude
	alert.Info[0].Area[0].Ceiling = &ceiling
	alert.Info[0].Area[0].Circle = []string{"45,-75 10"}
	alert.Info[0].Resource = []cap.Resource{{
		ResourceDesc: "Text attachment",
		MimeType:     "text/plain",
		Size:         &size,
		URI:          "attachment.txt",
		DerefURI:     base64.StdEncoding.EncodeToString(contents),
		Digest:       base64.StdEncoding.EncodeToString(digest[:]),
	}}
	alert.Extensions = []cap.Extension{{
		XMLName:  xml.Name{Space: "http://www.w3.org/2000/09/xmldsig#", Local: "extra"},
		InnerXML: "<value>preserved</value>",
	}}

	data, err := cap.MarshalCAP(alert)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, xml.Header) || strings.Contains(text, "<effective>") {
		t.Fatalf("unexpected XML: %s", text)
	}
	if !strings.Contains(text, "<altitude>0</altitude>") {
		t.Fatalf("zero altitude was omitted: %s", text)
	}

	parsed, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Info[0].Area[0].Altitude == nil || *parsed.Info[0].Area[0].Altitude != 0 {
		t.Fatalf("altitude = %#v", parsed.Info[0].Area[0].Altitude)
	}
	area := parsed.Info[0].Area[0]
	if area.Ceiling == nil || *area.Ceiling != ceiling || len(area.Circle) != 1 {
		t.Fatalf("area optional fields = %#v", area)
	}
	resource := parsed.Info[0].Resource[0]
	if resource.Size == nil || *resource.Size != size || resource.DerefURI == "" || resource.Digest == "" {
		t.Fatalf("resource optional fields = %#v", resource)
	}
	if len(parsed.Extensions) != 1 || parsed.Extensions[0].XMLName.Local != "extra" ||
		!strings.Contains(parsed.Extensions[0].InnerXML, "preserved") {
		t.Fatalf("extensions = %#v", parsed.Extensions)
	}
}

// TestMarshalCAPErrors checks invalid marshal inputs.
func TestMarshalCAPErrors(t *testing.T) {
	if _, err := cap.MarshalCAP(nil); err == nil {
		t.Fatal("expected nil alert error")
	}

	alert := validAlert(t)
	alert.Status = 0
	if _, err := cap.MarshalCAP(alert); err == nil {
		t.Fatal("expected invalid status error")
	}

	alert.Status = cap.StatusTest
	alert.Extensions = []cap.Extension{{XMLName: xml.Name{Space: "urn:example", Local: "extra"}}}
	if _, err := cap.MarshalCAP(alert); err == nil {
		t.Fatal("expected invalid extension error")
	}
}
