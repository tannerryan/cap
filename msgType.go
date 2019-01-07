// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// MsgType is a code denoting the appropriate handling of the alert message
type MsgType int

const (
	// MsgTypeAlert :: Initial information requiring attention by targeted
	// recipients
	MsgTypeAlert MsgType = 0
	// MsgTypeUpdate :: Updates and supercedes the earlier message(s) identified
	// in References
	MsgTypeUpdate MsgType = 1
	// MsgTypeCancel :: Cancels the earlier message(s) identified in References
	MsgTypeCancel MsgType = 2
	// MsgTypeAck :: Acknowledges receipt and acceptance of the message(s)
	// identified in References
	MsgTypeAck MsgType = 3
	// MsgTypeError :: Indicates rejection of the message(s) identified in
	// References; explanation SHOULD appear in Note
	MsgTypeError MsgType = 4
)

// MsgType mapping
var (
	MsgTypeMapping = map[string]MsgType{
		"Alert":  MsgTypeAlert,
		"Update": MsgTypeUpdate,
		"Cancel": MsgTypeCancel,
		"Ack":    MsgTypeAck,
		"Error":  MsgTypeError,
	}
)

// stringToCode will perform the mapping of string to a MsgType code. An error
// will be thrown if an unknown value is encountered.
func stringToMsgTypeCode(t *MsgType, val string) error {
	enum, ok := MsgTypeMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for MsgType code")
	}
	*t = enum
	return nil
}

// String converts the MsgType code back to a string.
func (t MsgType) String() string {
	for key, val := range MsgTypeMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// MsgType code.
func (t *MsgType) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToMsgTypeCode(t, val)
}

// MarshalXML converts the MsgType code back to a string when marshaling XML.
func (t MsgType) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// MsgType code.
func (t *MsgType) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToMsgTypeCode(t, val)
}

// MarshalJSON converts the MsgType code back to a string when marshaling JSON.
func (t MsgType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
