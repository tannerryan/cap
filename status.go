// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Status describes how recipients should handle an alert.
type Status int

const (
	// StatusActual is actionable by all targeted recipients.
	StatusActual Status = iota + 1
	// StatusExercise is actionable only by exercise participants.
	StatusExercise
	// StatusSystem is for alert system functions.
	StatusSystem
	// StatusTest is for technical testing.
	StatusTest
	// StatusDraft is a draft and is not actionable.
	StatusDraft
)

// StatusMapping maps CAP status values to Status constants. Callers must not
// modify it.
var StatusMapping = map[string]Status{
	"Actual":   StatusActual,
	"Exercise": StatusExercise,
	"System":   StatusSystem,
	"Test":     StatusTest,
	"Draft":    StatusDraft,
}

// stringToStatusCode parses a CAP status value.
func stringToStatusCode(t *Status, val string) error {
	enum, ok := StatusMapping[val]
	if !ok {
		return errors.New("cap: invalid Status value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP status value.
func (t Status) String() string {
	for key, val := range StatusMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP status value.
func (t *Status) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToStatusCode(t, val)
}

// MarshalXML encodes a CAP status value.
func (t Status) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Status")
}

// UnmarshalJSON decodes a CAP status value.
func (t *Status) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToStatusCode(t, val)
}

// MarshalJSON encodes a CAP status value.
func (t Status) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Status")
}
