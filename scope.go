// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Scope identifies the intended distribution of an alert message.
type Scope int

const (
	// ScopePublic allows general distribution.
	ScopePublic Scope = iota + 1
	// ScopeRestricted limits distribution using Restriction.
	ScopeRestricted
	// ScopePrivate limits distribution to Addresses.
	ScopePrivate
)

// ScopeMapping maps CAP scope values to Scope constants. Callers must not
// modify it.
var ScopeMapping = map[string]Scope{
	"Public":     ScopePublic,
	"Restricted": ScopeRestricted,
	"Private":    ScopePrivate,
}

// stringToScopeCode parses a CAP scope value.
func stringToScopeCode(t *Scope, val string) error {
	enum, ok := ScopeMapping[val]
	if !ok {
		return errors.New("cap: invalid Scope value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP scope value.
func (t Scope) String() string {
	for key, val := range ScopeMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP scope value.
func (t *Scope) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToScopeCode(t, val)
}

// MarshalXML encodes a CAP scope value.
func (t Scope) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Scope")
}

// UnmarshalJSON decodes a CAP scope value.
func (t *Scope) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToScopeCode(t, val)
}

// MarshalJSON encodes a CAP scope value.
func (t Scope) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Scope")
}
