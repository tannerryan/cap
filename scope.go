// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Scope is a code denoting the appropriate handling of the alert message
type Scope int

const (
	// ScopePublic :: For general dissemination to unrestricted audiences
	ScopePublic Scope = 0
	// ScopeRestricted :: For dissemination only to users with a known
	// operational requirement (see Restriction, below)
	ScopeRestricted Scope = 1
	// ScopePrivate :: For dissemination only to specified addresses (see
	// Addresses, below)
	ScopePrivate Scope = 2
)

// Scope mapping
var (
	ScopeMapping = map[string]Scope{
		"Public":     ScopePublic,
		"Restricted": ScopeRestricted,
		"Private":    ScopePrivate,
	}
)

// stringToCode will perform the mapping of string to a Scope code. An error
// will be thrown if an unknown value is encountered.
func stringToScopeCode(t *Scope, val string) error {
	enum, ok := ScopeMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Scope code")
	}
	*t = enum
	return nil
}

// String converts the Scope code back to a string.
func (t Scope) String() string {
	for key, val := range ScopeMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to Scope
// code.
func (t *Scope) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToScopeCode(t, val)
}

// MarshalXML converts the Scope code back to a string when marshaling XML.
func (t Scope) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Scope code.
func (t *Scope) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToScopeCode(t, val)
}

// MarshalJSON converts the Scope code back to a string when marshaling JSON.
func (t Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
