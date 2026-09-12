// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Severity identifies the severity of an alert's subject event.
type Severity int

const (
	// SeverityExtreme means an extraordinary threat to life or property.
	SeverityExtreme Severity = iota + 1
	// SeveritySevere means a significant threat to life or property.
	SeveritySevere
	// SeverityModerate means a possible threat to life or property.
	SeverityModerate
	// SeverityMinor means little or no known threat to life or property.
	SeverityMinor
	// SeverityUnknown means the severity is unknown.
	SeverityUnknown
)

// SeverityMapping maps CAP severity values to Severity constants. Callers must
// not modify it.
var SeverityMapping = map[string]Severity{
	"Extreme":  SeverityExtreme,
	"Severe":   SeveritySevere,
	"Moderate": SeverityModerate,
	"Minor":    SeverityMinor,
	"Unknown":  SeverityUnknown,
}

// stringToSeverityCode parses a CAP severity value.
func stringToSeverityCode(t *Severity, val string) error {
	enum, ok := SeverityMapping[val]
	if !ok {
		return errors.New("cap: invalid Severity value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP severity value.
func (t Severity) String() string {
	for key, val := range SeverityMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP severity value.
func (t *Severity) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToSeverityCode(t, val)
}

// MarshalXML encodes a CAP severity value.
func (t Severity) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Severity")
}

// UnmarshalJSON decodes a CAP severity value.
func (t *Severity) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToSeverityCode(t, val)
}

// MarshalJSON encodes a CAP severity value.
func (t Severity) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Severity")
}
