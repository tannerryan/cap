// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// MsgType identifies the nature of an alert message.
type MsgType int

const (
	// MsgTypeAlert provides new information that needs attention.
	MsgTypeAlert MsgType = iota + 1
	// MsgTypeUpdate replaces the messages listed in References.
	MsgTypeUpdate
	// MsgTypeCancel cancels the messages listed in References.
	MsgTypeCancel
	// MsgTypeAck accepts the messages listed in References.
	MsgTypeAck
	// MsgTypeError rejects the messages listed in References.
	MsgTypeError
)

// MsgTypeMapping maps CAP message type values to MsgType constants. Callers
// must not modify it.
var MsgTypeMapping = map[string]MsgType{
	"Alert":  MsgTypeAlert,
	"Update": MsgTypeUpdate,
	"Cancel": MsgTypeCancel,
	"Ack":    MsgTypeAck,
	"Error":  MsgTypeError,
}

// stringToMsgTypeCode parses a CAP message type value.
func stringToMsgTypeCode(t *MsgType, val string) error {
	enum, ok := MsgTypeMapping[val]
	if !ok {
		return errors.New("cap: invalid MsgType value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP message type value.
func (t MsgType) String() string {
	for key, val := range MsgTypeMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP message type value.
func (t *MsgType) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToMsgTypeCode(t, val)
}

// MarshalXML encodes a CAP message type value.
func (t MsgType) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "MsgType")
}

// UnmarshalJSON decodes a CAP message type value.
func (t *MsgType) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToMsgTypeCode(t, val)
}

// MarshalJSON encodes a CAP message type value.
func (t MsgType) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "MsgType")
}
