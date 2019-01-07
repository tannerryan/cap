// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
)

// Category is a code denoting the appropriate handling of the alert message
type Category int

const (
	// CategoryGeo :: Geophysical (inc. landslide)
	CategoryGeo Category = 0
	// CategoryMet :: Meteorological (inc. flood)
	CategoryMet Category = 1
	// CategorySafety :: General emergency and public safety
	CategorySafety Category = 2
	// CategorySecurity :: Law enforcement, military, homeland and local/private
	// security
	CategorySecurity Category = 3
	// CategoryRescue :: Rescue and recovery
	CategoryRescue Category = 4
	// CategoryFire :: Fire suppression and rescue
	CategoryFire Category = 5
	// CategoryHealth :: Medical and public health
	CategoryHealth Category = 6
	// CategoryEnv :: Pollution and other environmental
	CategoryEnv Category = 7
	// CategoryTransport :: Public and private transportation
	CategoryTransport Category = 8
	// CategoryInfra :: Utility, telecommunication, other non-transport
	// infrastructure
	CategoryInfra Category = 9
	// CategoryCBRNE :: Chemical, Biological, Radiological, Nuclear or
	// High-Yield Explosive threat or attack
	CategoryCBRNE Category = 10
	// CategoryOther :: Other events
	CategoryOther Category = 11
)

// Category mapping
var (
	CategoryMapping = map[string]Category{
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
)

// stringToCode will perform the mapping of string to a Category code. An error
// will be thrown if an unknown value is encountered.
func stringToCategoryCode(t *Category, val string) error {
	enum, ok := CategoryMapping[val]
	if !ok {
		return errors.New("Error: illegal value " + val + " for Category code")
	}
	*t = enum
	return nil
}

// String converts the Category code back to a string.
func (t Category) String() string {
	for key, val := range CategoryMapping {
		if val == t {
			return key
		}
	}
	// logically never reached
	return ""
}

// UnmarshalXML will be used during the XML unmarshaling for conversion to
// Category code.
func (t *Category) UnmarshalXML(decoder *xml.Decoder, elem xml.StartElement) error {
	var val string
	if err := decoder.DecodeElement(&val, &elem); err != nil {
		return err
	}
	return stringToCategoryCode(t, val)
}

// MarshalXML converts the Category code back to a string when marshaling XML.
func (t Category) MarshalXML(encoder *xml.Encoder, elem xml.StartElement) error {
	return encoder.EncodeElement(t.String(), elem)
}

// UnmarshalJSON will be used during the JSON unmarshaling for conversion to
// Category code.
func (t *Category) UnmarshalJSON(buff []byte) error {
	var val string
	if err := json.Unmarshal(buff, &val); err != nil {
		return err
	}
	return stringToCategoryCode(t, val)
}

// MarshalJSON converts the Category code back to a string when marshaling JSON.
func (t Category) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
