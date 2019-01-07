// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Certainty is a code denoting the appropriate handling of the alert message
type Certainty int

const (
	// CertaintyObserved :: Determined to have occurred or to be ongoing
	CertaintyObserved Certainty = 0
	// CertaintyLikely :: Likely (p > ~50%)
	CertaintyLikely Certainty = 1
	// CertaintyPossible :: Possible but not likely (p <= ~50%)
	CertaintyPossible Certainty = 2
	// CertaintyUnlikely :: Not expected to occur (p ~ 0)
	CertaintyUnlikely Certainty = 3
	// CertaintyUnknown :: Certainty unknown
	CertaintyUnknown Certainty = 4
)

// Certainty mapping
var (
	CertaintyMapping = map[string]Certainty{
		"Observed": CertaintyObserved,
		"Likely":   CertaintyLikely,
		"Possible": CertaintyPossible,
		"Unlikely": CertaintyUnlikely,
		"Unknown":  CertaintyUnknown,
	}
)

// stringToCode will perform the mapping of string to a Certainty code. An error
// will be thrown if an unknown value is encountered.
func stringToCertaintyCode(t *Certainty, val string) error {
	enum, ok := CertaintyMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Certainty code")
	}
	*t = enum
	return nil
}

// String converts the Certainty code back to a string.
func (t Certainty) String() string {
	for key, val := range CertaintyMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// Certainty code.
func (t *Certainty) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToCertaintyCode(t, val)
}

// MarshalXML converts the Certainty code back to a string when marshaling XML.
func (t Certainty) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Certainty code.
func (t *Certainty) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToCertaintyCode(t, val)
}

// MarshalJSON converts the Certainty code back to a string when marshaling
// JSON.
func (t Certainty) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
