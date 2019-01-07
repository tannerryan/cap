// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Severity is a code denoting the appropriate handling of the alert message
type Severity int

const (
	// SeverityExtreme :: Extraordinary threat to life or property
	SeverityExtreme Severity = 0
	// SeveritySevere :: Significant threat to life or property
	SeveritySevere Severity = 1
	// SeverityModerate :: Possible threat to life or property
	SeverityModerate Severity = 2
	// SeverityMinor :: Minimal to no known threat to life or property
	SeverityMinor Severity = 3
	// SeverityUnknown :: Severity unknown
	SeverityUnknown Severity = 4
)

// Severity mapping
var (
	SeverityMapping = map[string]Severity{
		"Extreme":  SeverityExtreme,
		"Severe":   SeveritySevere,
		"Moderate": SeverityModerate,
		"Minor":    SeverityMinor,
		"Unknown":  SeverityUnknown,
	}
)

// stringToCode will perform the mapping of string to a Severity code. An error
// will be thrown if an unknown value is encountered.
func stringToSeverityCode(t *Severity, val string) error {
	enum, ok := SeverityMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Severity code")
	}
	*t = enum
	return nil
}

// String converts the Severity code back to a string.
func (t Severity) String() string {
	for key, val := range SeverityMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// Severity code.
func (t *Severity) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToSeverityCode(t, val)
}

// MarshalXML converts the Severity code back to a string when marshaling XML.
func (t Severity) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Severity code.
func (t *Severity) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToSeverityCode(t, val)
}

// MarshalJSON converts the Severity code back to a string when marshaling JSON.
func (t Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
