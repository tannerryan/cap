// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// ResponseType is a code denoting the appropriate handling of the alert message
type ResponseType int

const (
	// ResponseTypeShelter :: Take shelter in place or per Instruction
	ResponseTypeShelter ResponseType = 0
	// ResponseTypeEvacuate :: Relocate as instructed in the Instruction
	ResponseTypeEvacuate ResponseType = 1
	// ResponseTypePrepare :: Make preparations per the Instruction
	ResponseTypePrepare ResponseType = 2
	// ResponseTypeExecute :: Execute a pre-planned activity identified in
	// Instruction
	ResponseTypeExecute ResponseType = 3
	// ResponseTypeAvoid :: Avoid the subject event as per the Instruction
	ResponseTypeAvoid ResponseType = 4
	// ResponseTypeMonitor :: Attend to information sources as described in
	// Instruction
	ResponseTypeMonitor ResponseType = 5
	// ResponseTypeAssess :: Evaluate the information in this message.  (This
	// value SHOULD NOT be used in public warning applications.)
	ResponseTypeAssess ResponseType = 6
	// ResponseTypeAllClear :: The subject event no longer poses a threat or
	// concern and any follow on action is described in Instruction
	ResponseTypeAllClear ResponseType = 7
	// ResponseTypeNone :: No action recommended
	ResponseTypeNone ResponseType = 8
)

// ResponseType mapping
var (
	ResponseTypeMapping = map[string]ResponseType{
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
)

// stringToCode will perform the mapping of string to a ResponseType code. An
// error will be thrown if an unknown value is encountered.
func stringToResponseTypeCode(t *ResponseType, val string) error {
	enum, ok := ResponseTypeMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for ResponseType code")
	}
	*t = enum
	return nil
}

// String converts the ResponseType code back to a string.
func (t ResponseType) String() string {
	for key, val := range ResponseTypeMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// ResponseType code.
func (t *ResponseType) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToResponseTypeCode(t, val)
}

// MarshalXML converts the ResponseType code back to a string when marshaling
// XML.
func (t ResponseType) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// ResponseType code.
func (t *ResponseType) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToResponseTypeCode(t, val)
}

// MarshalJSON converts the ResponseType code back to a string when marshaling
// JSON.
func (t ResponseType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
