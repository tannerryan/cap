// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Urgency identifies the urgency of an alert's subject event.
type Urgency int

const (
	// UrgencyImmediate calls for immediate action.
	UrgencyImmediate Urgency = iota + 1
	// UrgencyExpected calls for action within the next hour.
	UrgencyExpected
	// UrgencyFuture calls for action later than the next hour.
	UrgencyFuture
	// UrgencyPast means action is no longer needed.
	UrgencyPast
	// UrgencyUnknown means the urgency is unknown.
	UrgencyUnknown
)

// UrgencyMapping maps CAP urgency values to Urgency constants. Callers must not
// modify it.
var UrgencyMapping = map[string]Urgency{
	"Immediate": UrgencyImmediate,
	"Expected":  UrgencyExpected,
	"Future":    UrgencyFuture,
	"Past":      UrgencyPast,
	"Unknown":   UrgencyUnknown,
}

// stringToUrgencyCode parses a CAP urgency value.
func stringToUrgencyCode(t *Urgency, val string) error {
	enum, ok := UrgencyMapping[val]
	if !ok {
		return errors.New("cap: invalid Urgency value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP urgency value.
func (t Urgency) String() string {
	for key, val := range UrgencyMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP urgency value.
func (t *Urgency) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToUrgencyCode(t, val)
}

// MarshalXML encodes a CAP urgency value.
func (t Urgency) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Urgency")
}

// UnmarshalJSON decodes a CAP urgency value.
func (t *Urgency) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToUrgencyCode(t, val)
}

// MarshalJSON encodes a CAP urgency value.
func (t Urgency) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Urgency")
}
