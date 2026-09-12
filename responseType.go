// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// ResponseType identifies an action recommended for the target audience.
type ResponseType int

const (
	// ResponseTypeShelter tells recipients to take shelter.
	ResponseTypeShelter ResponseType = iota + 1
	// ResponseTypeEvacuate tells recipients to relocate.
	ResponseTypeEvacuate
	// ResponseTypePrepare tells recipients to prepare.
	ResponseTypePrepare
	// ResponseTypeExecute tells recipients to carry out a planned action.
	ResponseTypeExecute
	// ResponseTypeAvoid tells recipients to avoid the event.
	ResponseTypeAvoid
	// ResponseTypeMonitor tells recipients to monitor information sources.
	ResponseTypeMonitor
	// ResponseTypeAssess tells recipients to assess the information.
	ResponseTypeAssess
	// ResponseTypeAllClear means the event no longer poses a threat.
	ResponseTypeAllClear
	// ResponseTypeNone means no action is recommended.
	ResponseTypeNone
)

// ResponseTypeMapping maps CAP response values to ResponseType constants.
// Callers must not modify it.
var ResponseTypeMapping = map[string]ResponseType{
	"Shelter":  ResponseTypeShelter,
	"Evacuate": ResponseTypeEvacuate,
	"Prepare":  ResponseTypePrepare,
	"Execute":  ResponseTypeExecute,
	"Avoid":    ResponseTypeAvoid,
	"Monitor":  ResponseTypeMonitor,
	"Assess":   ResponseTypeAssess,
	"AllClear": ResponseTypeAllClear,
	"None":     ResponseTypeNone,
}

// stringToResponseTypeCode parses a CAP response value.
func stringToResponseTypeCode(t *ResponseType, val string) error {
	enum, ok := ResponseTypeMapping[val]
	if !ok {
		return errors.New("cap: invalid ResponseType value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP response value.
func (t ResponseType) String() string {
	for key, val := range ResponseTypeMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP response value.
func (t *ResponseType) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToResponseTypeCode(t, val)
}

// MarshalXML encodes a CAP response value.
func (t ResponseType) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "ResponseType")
}

// UnmarshalJSON decodes a CAP response value.
func (t *ResponseType) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToResponseTypeCode(t, val)
}

// MarshalJSON encodes a CAP response value.
func (t ResponseType) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "ResponseType")
}
