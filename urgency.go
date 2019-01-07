// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Urgency is a code denoting the appropriate handling of the alert message
type Urgency int

const (
	// UrgencyImmediate :: Responsive action SHOULD be taken immediately
	UrgencyImmediate Urgency = 0
	// UrgencyExpected :: Responsive action SHOULD be taken soon (within next
	// hour)
	UrgencyExpected Urgency = 1
	// UrgencyFuture :: Responsive action SHOULD be taken soon (within next
	// hour)
	UrgencyFuture Urgency = 2
	// UrgencyPast ::  Responsive action is no longer required
	UrgencyPast Urgency = 3
	// UrgencyUnknown :: Urgency not known
	UrgencyUnknown Urgency = 4
)

// Urgency mapping
var (
	UrgencyMapping = map[string]Urgency{
		"Immediate": UrgencyImmediate,
		"Expected":  UrgencyExpected,
		"Future":    UrgencyFuture,
		"Past":      UrgencyPast,
		"Unknown":   UrgencyUnknown,
	}
)

// stringToCode will perform the mapping of string to a Urgency code. An error
// will be thrown if an unknown value is encountered.
func stringToUrgencyCode(t *Urgency, val string) error {
	enum, ok := UrgencyMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Urgency code")
	}
	*t = enum
	return nil
}

// String converts the Urgency code back to a string.
func (t Urgency) String() string {
	for key, val := range UrgencyMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// Urgency code.
func (t *Urgency) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToUrgencyCode(t, val)
}

// MarshalXML converts the Urgency code back to a string when marshaling XML.
func (t Urgency) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Urgency code.
func (t *Urgency) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToUrgencyCode(t, val)
}

// MarshalJSON converts the Urgency code back to a string when marshaling JSON.
func (t Urgency) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
