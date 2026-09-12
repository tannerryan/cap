// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Certainty identifies the certainty of an alert's subject event.
type Certainty int

const (
	// CertaintyObserved means the event has occurred or is underway.
	CertaintyObserved Certainty = iota + 1
	// CertaintyLikely means the event is more likely than not. The parser also
	// accepts the deprecated CAP 1.0 value "Very Likely" as this value.
	CertaintyLikely
	// CertaintyPossible means the event is possible but not likely.
	CertaintyPossible
	// CertaintyUnlikely means the event is not expected.
	CertaintyUnlikely
	// CertaintyUnknown means the certainty is unknown.
	CertaintyUnknown
)

// CertaintyMapping maps CAP certainty values to Certainty constants. Callers
// must not modify it.
var CertaintyMapping = map[string]Certainty{
	"Observed": CertaintyObserved,
	"Likely":   CertaintyLikely,
	"Possible": CertaintyPossible,
	"Unlikely": CertaintyUnlikely,
	"Unknown":  CertaintyUnknown,
}

// stringToCertaintyCode parses a CAP certainty value.
func stringToCertaintyCode(t *Certainty, val string) error {
	if val == "Very Likely" {
		*t = CertaintyLikely
		return nil
	}
	enum, ok := CertaintyMapping[val]
	if !ok {
		return errors.New("cap: invalid Certainty value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP certainty value.
func (t Certainty) String() string {
	for key, val := range CertaintyMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP certainty value.
func (t *Certainty) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToCertaintyCode(t, val)
}

// MarshalXML encodes a CAP certainty value.
func (t Certainty) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Certainty")
}

// UnmarshalJSON decodes a CAP certainty value.
func (t *Certainty) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToCertaintyCode(t, val)
}

// MarshalJSON encodes a CAP certainty value.
func (t Certainty) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Certainty")
}
