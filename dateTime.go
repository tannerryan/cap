// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"time"
)

// DateTime is to represent a time field in an Alert
type DateTime struct {
	val time.Time
}

// XML dateTime format (as implemented in CAP 1.2)
var timeFormat = "2006-01-02T15:04:05-07:00"

// String returns the XML dateTime representation of the DateTime
func (t DateTime) String() string {
	obj := t.val.Format(timeFormat)
	return strings.Replace(obj, "+00:00", "-00:00", 1)
}

// parseTime will initialize a dateTime struct given a XML dateTime string. If
// the string is not formatted correctly, an error will be returned.
func parseTime(t *DateTime, val string) error {
	timeObj, err := time.Parse(timeFormat, val)
	if err != nil {
		return err
	}
	t.val = timeObj
	return nil
}

// Time returns a standard time struct for the DateTime
func (t *DateTime) Time() time.Time {
	return t.val
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// DateTime.
func (t *DateTime) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return parseTime(t, val)
}

// MarshalXML converts the DateTime back to a string when marshaling XML.
func (t DateTime) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// DateTime.
func (t *DateTime) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return parseTime(t, val)
}

// MarshalJSON converts the DateTime back to a string when marshaling JSON.
func (t DateTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
