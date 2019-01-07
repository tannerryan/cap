// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Status is a code denoting the appropriate handling of the alert message
type Status int

const (
	// StatusActual :: Actionable by all targeted recipients
	StatusActual Status = 0
	// StatusExercise :: Actionable only by designated exercise participants;
	// exercise identifier SHOULD appear in Note
	StatusExercise Status = 1
	// StatusSystem :: For messages that support alert network internal
	// functions
	StatusSystem Status = 2
	// StatusTest :: Technical testing only, all recipients disregard
	StatusTest Status = 3
	// StatusDraft :: A preliminary template or draft, not actionable in its
	// current form
	StatusDraft Status = 4
)

// Status mapping
var (
	StatusMapping = map[string]Status{
		"Actual":   StatusActual,
		"Exercise": StatusExercise,
		"System":   StatusSystem,
		"Test":     StatusTest,
		"Draft":    StatusDraft,
	}
)

// stringToCode will perform the mapping of string to a Status code. An error
// will be thrown if an unknown value is encountered.
func stringToStatusCode(t *Status, val string) error {
	enum, ok := StatusMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Status code")
	}
	*t = enum
	return nil
}

// String converts the Status code back to a string.
func (t Status) String() string {
	for key, val := range StatusMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// Status code.
func (t *Status) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToStatusCode(t, val)
}

// MarshalXML converts the Status code back to a string when marshaling XML.
func (t Status) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Status code.
func (t *Status) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToStatusCode(t, val)
}

// MarshalJSON converts the Status code back to a string when marshaling JSON.
func (t Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
