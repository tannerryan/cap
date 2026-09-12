// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

// List represents whitespace-delimited CAP values.
type List struct {
	val []string // Parsed list values.
}

// listDelimiter separates values when a list is encoded.
const listDelimiter = " "

// NewList returns a list containing a copy of values.
func NewList(values ...string) List {
	return List{val: append([]string(nil), values...)}
}

// String returns the values joined with spaces.
func (t List) String() string {
	return strings.Join(t.val, listDelimiter)
}

// parseString initializes a List from whitespace-delimited values.
func parseString(t *List, val string) {
	t.val = strings.Fields(val)
}

// Values returns the values in the list.
func (t List) Values() []string {
	return append([]string(nil), t.val...)
}

// UnmarshalXML decodes a whitespace-delimited CAP list.
func (t *List) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	parseString(t, val)
	return nil
}

// MarshalXML encodes a whitespace-delimited CAP list.
func (t List) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON decodes a whitespace-delimited CAP list.
func (t *List) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	parseString(t, val)
	return nil
}

// MarshalJSON encodes a whitespace-delimited CAP list.
func (t List) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
