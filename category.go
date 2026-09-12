// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Category identifies the category of an alert's subject event.
type Category int

const (
	// CategoryGeo covers geophysical events such as landslides.
	CategoryGeo Category = iota + 1
	// CategoryMet covers weather events, including floods.
	CategoryMet
	// CategorySafety covers general emergencies and public safety.
	CategorySafety
	// CategorySecurity covers law enforcement, military, and security events.
	CategorySecurity
	// CategoryRescue covers rescue and recovery.
	CategoryRescue
	// CategoryFire covers fire suppression and rescue.
	CategoryFire
	// CategoryHealth covers medical and public health events.
	CategoryHealth
	// CategoryEnv covers pollution and other environmental events.
	CategoryEnv
	// CategoryTransport covers public and private transportation.
	CategoryTransport
	// CategoryInfra covers utilities and other infrastructure.
	CategoryInfra
	// CategoryCBRNE covers chemical, biological, radiological, nuclear, and
	// explosive threats.
	CategoryCBRNE
	// CategoryOther covers events outside the other categories.
	CategoryOther
)

// CategoryMapping maps CAP category values to Category constants. Callers must
// not modify it.
var CategoryMapping = map[string]Category{
	"Geo":       CategoryGeo,
	"Met":       CategoryMet,
	"Safety":    CategorySafety,
	"Security":  CategorySecurity,
	"Rescue":    CategoryRescue,
	"Fire":      CategoryFire,
	"Health":    CategoryHealth,
	"Env":       CategoryEnv,
	"Transport": CategoryTransport,
	"Infra":     CategoryInfra,
	"CBRNE":     CategoryCBRNE,
	"Other":     CategoryOther,
}

// stringToCategoryCode parses a CAP category value.
func stringToCategoryCode(t *Category, val string) error {
	enum, ok := CategoryMapping[val]
	if !ok {
		return errors.New("cap: invalid Category value " + val)
	}
	*t = enum
	return nil
}

// String returns the CAP category value.
func (t Category) String() string {
	for key, val := range CategoryMapping {
		if val == t {
			return key
		}
	}
	return ""
}

// UnmarshalXML decodes a CAP category value.
func (t *Category) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToCategoryCode(t, val)
}

// MarshalXML encodes a CAP category value.
func (t Category) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return marshalEnumXML(encoder, elem, t.String(), "Category")
}

// UnmarshalJSON decodes a CAP category value.
func (t *Category) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToCategoryCode(t, val)
}

// MarshalJSON encodes a CAP category value.
func (t Category) MarshalJSON() ([]byte, error) {
	return marshalEnumJSON(t.String(), "Category")
}
