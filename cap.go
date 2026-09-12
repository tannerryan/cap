// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// capNamespace is the XML namespace for CAP 1.2.
const capNamespace = "urn:oasis:names:tc:emergency:cap:1.2"

// xmlSignatureNamespace is the XML namespace allowed for CAP extensions.
const xmlSignatureNamespace = "http://www.w3.org/2000/09/xmldsig#"

// ParseCAP decodes an XML CAP 1.2 message. It checks XML syntax, namespaces,
// dates, and code values. Use Validate or ValidateCAPCP for message rules.
func ParseCAP(data []byte) (*Alert, error) {
	if err := checkCAPNamespaces(data); err != nil {
		return nil, err
	}
	var alert Alert
	err := xml.Unmarshal(data, &alert)
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

// checkCAPNamespaces prevents foreign elements from filling CAP fields.
func checkCAPNamespaces(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	extensionDepth := -1
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				if rootSeen {
					return errors.New("cap: XML document has multiple root elements")
				}
				if token.Name.Space != capNamespace || token.Name.Local != "alert" {
					return errors.New("cap: invalid CAP namespace or root element")
				}
				rootSeen = true
			} else if extensionDepth < 0 {
				if depth == 1 && token.Name.Space == xmlSignatureNamespace {
					extensionDepth = depth
				} else if token.Name.Space != capNamespace {
					return fmt.Errorf("cap: element %q must use the CAP namespace", token.Name.Local)
				}
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == extensionDepth {
				extensionDepth = -1
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(token)) != "" {
				return errors.New("cap: data outside the root element")
			}
		}
	}
}

// MarshalCAP encodes an alert as an indented CAP XML document. Re-encoding a
// signed alert does not preserve its signature validity.
func MarshalCAP(alert *Alert) ([]byte, error) {
	if alert == nil {
		return nil, errors.New("cap: nil alert")
	}
	for i, extension := range alert.Extensions {
		if extension.XMLName.Space != xmlSignatureNamespace {
			return nil, fmt.Errorf("cap: extension %d must use the XML Signature namespace", i)
		}
	}
	copy := *alert
	if copy.XMLName.Local == "" {
		copy.XMLName = xml.Name{Space: capNamespace, Local: "alert"}
	}
	body, err := xml.MarshalIndent(&copy, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}
