// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// marshalEnumXML encodes a checked CAP enum value.
func marshalEnumXML(encoder *xml.Encoder, elem xml.StartElement, value, name string) error {
	if value == "" {
		return errors.New("cap: invalid " + name + " value")
	}
	return encoder.EncodeElement(value, elem)
}

// marshalEnumJSON encodes a checked CAP enum value.
func marshalEnumJSON(value, name string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("cap: invalid " + name + " value")
	}
	return json.Marshal(value)
}
