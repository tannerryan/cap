// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

// List is to represent delimeted string values
type List struct {
	val []string
}

// listDelimeter is for joining/splitting values
var listDelimeter = " "

// String returns the a joined string representation of the values, delimeted
// with the listDelimeter.
func (t *List) String() string {
	return strings.Join(t.val, listDelimeter)
}

// parseString will initilize a List struct given a string of values, separated
// by the listDelimeter
func parseString(t *List, val string) error {
	vals := strings.Split(val, listDelimeter)
	t.val = vals
	return nil
}

// Values returns a standard string slice .
func (t *List) Values() []string {
	return t.val
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to List.
func (t *List) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return parseString(t, val)
}

// MarshalXML converts the List back to a string when marshaling XML.
func (t List) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// List.
func (t *List) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return parseString(t, val)
}

// MarshalJSON converts the List back to a string when marshaling JSON.
func (t List) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
