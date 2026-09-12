// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
	"time"
)

// DateTime represents a CAP date-time with a numeric UTC offset.
type DateTime struct {
	val time.Time // Parsed date and time.
}

// CAP uses a numeric UTC offset and does not allow Z.
const timeFormat = "2006-01-02T15:04:05-07:00"

// NewDateTime returns a CAP date-time for value. It rejects values that CAP
// cannot represent.
func NewDateTime(value time.Time) (DateTime, error) {
	if err := validateTimeValue(value); err != nil {
		return DateTime{}, err
	}
	return DateTime{val: value}, nil
}

// ParseDateTime parses a CAP date-time value, including its numeric offset.
func ParseDateTime(value string) (DateTime, error) {
	var result DateTime
	err := parseTime(&result, value)
	return result, err
}

// String returns the CAP date and time value.
func (t DateTime) String() string {
	obj := t.val.Format(timeFormat)
	return strings.Replace(obj, "+00:00", "-00:00", 1)
}

// parseTime parses a CAP date and time value.
func parseTime(t *DateTime, val string) error {
	val = strings.TrimSpace(val)
	timeObj, err := time.Parse(timeFormat, val)
	if err != nil {
		return err
	}
	if strings.HasSuffix(val, "+00:00") {
		return errors.New("cap: UTC date-time must use -00:00")
	}
	if err := validateTimeValue(timeObj); err != nil {
		return err
	}
	if (DateTime{val: timeObj}).String() != val {
		return errors.New("cap: date-time must use the CAP format YYYY-MM-DDThh:mm:ssXhh:mm")
	}
	t.val = timeObj
	return nil
}

// validateTimeValue checks whether a time can be represented by CAP.
func validateTimeValue(value time.Time) error {
	if value.Year() < 1 || value.Year() > 9999 || value.Nanosecond() != 0 {
		return errors.New("cap: date-time must use a four-digit year and whole seconds")
	}
	_, offset := value.Zone()
	if offset%60 != 0 || offset < -14*60*60 || offset > 14*60*60 {
		return errors.New("cap: date-time offset must be within 14 hours and use whole minutes")
	}
	return nil
}

// Time returns the value as a time.Time.
func (t DateTime) Time() time.Time {
	return t.val
}

// IsZero reports whether no time has been assigned.
func (t DateTime) IsZero() bool {
	return t.val.IsZero()
}

// UnmarshalXML decodes a CAP date and time value.
func (t *DateTime) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return parseTime(t, val)
}

// MarshalXML encodes a CAP date and time value.
func (t DateTime) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	if err := validateTimeValue(t.val); err != nil {
		return err
	}
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON decodes a CAP date and time value.
func (t *DateTime) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return parseTime(t, val)
}

// MarshalJSON encodes a CAP date and time value.
func (t DateTime) MarshalJSON() ([]byte, error) {
	if err := validateTimeValue(t.val); err != nil {
		return nil, err
	}
	return json.Marshal(t.String())
}
