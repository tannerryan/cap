// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/xml"
	"strings"
)

// Alert is a CAP message with routing details and optional event information.
type Alert struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:emergency:cap:1.2 alert" json:"-"` // CAP XML root.

	Identifier  string   `xml:"identifier" json:"identifier"`                       // Unique message ID. Required.
	Sender      string   `xml:"sender" json:"sender"`                               // Sender ID. Required.
	Sent        DateTime `xml:"sent" json:"sent"`                                   // Time the message was sent. Required.
	Status      Status   `xml:"status" json:"status"`                               // Message status. Required.
	MsgType     MsgType  `xml:"msgType" json:"msgType"`                             // Message type. Required.
	Source      string   `xml:"source,omitempty" json:"source,omitempty"`           // Message source.
	Scope       Scope    `xml:"scope" json:"scope"`                                 // Distribution scope. Required.
	Restriction string   `xml:"restriction,omitempty" json:"restriction,omitempty"` // Rule for restricted distribution.
	Addresses   string   `xml:"addresses,omitempty" json:"addresses,omitempty"`     // Intended recipient identifiers or addresses.
	Code        []string `xml:"code,omitempty" json:"code,omitempty"`               // Special handling codes.
	Note        string   `xml:"note,omitempty" json:"note,omitempty"`               // Message note.
	References  *List    `xml:"references,omitempty" json:"references,omitempty"`   // Earlier messages referenced by this message.
	Incidents   string   `xml:"incidents,omitempty" json:"incidents,omitempty"`     // Related incident IDs.

	Info       []Info      `xml:"info,omitempty" json:"info,omitempty"`           // Event details.
	Signature  []Signature `xml:"Signature,omitempty" json:"signature,omitempty"` // XML signatures.
	Extensions []Extension `xml:",any" json:"extensions,omitempty"`               // Additional XML Signature elements.
}

// Info describes an event and the action recipients should take. An alert may
// have several Info values for different areas or languages.
type Info struct {
	XMLName xml.Name `xml:"info" json:"-"` // CAP info element.

	Language     string         `xml:"language,omitempty" json:"language,omitempty"`         // Content language.
	Category     []Category     `xml:"category" json:"category"`                             // Event categories. At least one is required.
	Event        string         `xml:"event" json:"event"`                                   // Event name. Required.
	ResponseType []ResponseType `xml:"responseType,omitempty" json:"responseType,omitempty"` // Recommended actions.
	Urgency      Urgency        `xml:"urgency" json:"urgency"`                               // Event urgency. Required.
	Severity     Severity       `xml:"severity" json:"severity"`                             // Event severity. Required.
	Certainty    Certainty      `xml:"certainty" json:"certainty"`                           // Event certainty. Required.
	Audience     string         `xml:"audience,omitempty" json:"audience,omitempty"`         // Intended audience.
	EventCode    []KeyValue     `xml:"eventCode,omitempty" json:"eventCode,omitempty"`       // Event codes.
	Effective    *DateTime      `xml:"effective,omitempty" json:"effective,omitempty"`       // Time the information takes effect.
	Onset        *DateTime      `xml:"onset,omitempty" json:"onset,omitempty"`               // Expected start time.
	Expires      *DateTime      `xml:"expires,omitempty" json:"expires,omitempty"`           // Expiration time.
	SenderName   string         `xml:"senderName,omitempty" json:"senderName,omitempty"`     // Sender's display name.
	Headline     string         `xml:"headline,omitempty" json:"headline,omitempty"`         // Short headline.
	Description  string         `xml:"description,omitempty" json:"description,omitempty"`   // Event description.
	Instruction  string         `xml:"instruction,omitempty" json:"instruction,omitempty"`   // Instructions for recipients.
	Web          string         `xml:"web,omitempty" json:"web,omitempty"`                   // Link to more information.
	Contact      string         `xml:"contact,omitempty" json:"contact,omitempty"`           // Follow-up contact.
	Parameter    []KeyValue     `xml:"parameter,omitempty" json:"parameter,omitempty"`       // Extra system values.

	Resource []Resource `xml:"resource,omitempty" json:"resource,omitempty"` // Related files.
	Area     []Area     `xml:"area,omitempty" json:"area,omitempty"`         // Affected areas.
}

// LanguageCode returns Language, or the CAP default of en-US.
func (i Info) LanguageCode() string {
	language := strings.TrimSpace(i.Language)
	if language == "" {
		return "en-US"
	}
	return language
}

// EffectiveTime returns Effective, or the alert sent time when Effective is
// omitted.
func (i Info) EffectiveTime(sent DateTime) DateTime {
	if i.Effective == nil {
		return sent
	}
	return *i.Effective
}

// Resource describes a file related to an Info value.
type Resource struct {
	XMLName xml.Name `xml:"resource" json:"-"` // CAP resource element.

	ResourceDesc string `xml:"resourceDesc" json:"resourceDesc"`             // File description. Required.
	MimeType     string `xml:"mimeType" json:"mimeType"`                     // MIME type. Required.
	Size         *int64 `xml:"size,omitempty" json:"size,omitempty"`         // File size in bytes.
	URI          string `xml:"uri,omitempty" json:"uri,omitempty"`           // File location.
	DerefURI     string `xml:"derefUri,omitempty" json:"derefUri,omitempty"` // Base64 encoded file data.
	Digest       string `xml:"digest,omitempty" json:"digest,omitempty"`     // SHA-1 file digest.
}

// Area describes a place affected by an event.
type Area struct {
	XMLName xml.Name `xml:"area" json:"-"` // CAP area element.

	AreaDesc string     `xml:"areaDesc" json:"areaDesc"`                     // Area description. Required.
	Polygon  []List     `xml:"polygon,omitempty" json:"polygon,omitempty"`   // Affected polygons.
	Circle   []string   `xml:"circle,omitempty" json:"circle,omitempty"`     // Affected circles.
	Geocode  []KeyValue `xml:"geocode,omitempty" json:"geocode,omitempty"`   // Area codes.
	Altitude *float64   `xml:"altitude,omitempty" json:"altitude,omitempty"` // Altitude or lower bound in feet above mean sea level.
	Ceiling  *float64   `xml:"ceiling,omitempty" json:"ceiling,omitempty"`   // Upper bound in feet above mean sea level.
}

// KeyValue holds a named CAP value.
type KeyValue struct {
	ValueName string `xml:"valueName" json:"valueName"` // Name of the code or value domain.
	Value     string `xml:"value" json:"value"`         // Value within that domain.
}

// Signature holds commonly used fields from an enveloped XML signature.
type Signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature" json:"-"` // XML Signature element.

	ID                  string              `xml:"Id,attr" json:"id"`                                                     // Signature ID.
	SignedInfo          SignedInfo          `xml:"SignedInfo" json:"signedInfo"`                                          // Signed algorithms and references.
	SignatureValue      string              `xml:"SignatureValue" json:"signatureValue"`                                  // Encoded signature value.
	X509Certificate     []string            `xml:"KeyInfo>X509Data>X509Certificate" json:"x509Certificate"`               // Encoded certificates.
	SignatureProperties []SignatureProperty `xml:"Object>SignatureProperties>SignatureProperty" json:"signatureProperty"` // Signed properties.
}

// SignedInfo references signed data and specifies the algorithms used.
type SignedInfo struct {
	CanonicalizationMethod Algorithm   `xml:"CanonicalizationMethod" json:"canonicalizationMethod"` // Canonical XML algorithm.
	SignatureMethod        Algorithm   `xml:"SignatureMethod" json:"signatureMethod"`               // Signature algorithm.
	Reference              []Reference `xml:"Reference" json:"reference"`                           // Signed content references.
}

// Reference describes signed data and any transforms applied to it.
type Reference struct {
	URI          string      `xml:"URI,attr" json:"uri"`                   // Referenced content.
	Transform    []Algorithm `xml:"Transforms>Transform" json:"transform"` // Applied transforms.
	DigestMethod Algorithm   `xml:"DigestMethod" json:"digestMethod"`      // Digest algorithm.
	DigestValue  string      `xml:"DigestValue" json:"digestValue"`        // Encoded digest.
}

// SignatureProperty holds a property covered by a signature.
type SignatureProperty struct {
	ID      string  `xml:"Id,attr" json:"id"`         // Property ID.
	Target  string  `xml:"Target,attr" json:"target"` // Property target.
	XCValue XCValue `xml:"value" json:"value"`        // NAADS xc value.
}

// Algorithm names an XML signature algorithm.
type Algorithm struct {
	Algorithm string `xml:"Algorithm,attr" json:"algorithm"` // Algorithm URI.
}

// XCValue holds the xc namespace used by NAADS signatures.
type XCValue struct {
	XC string `xml:"xc,attr" json:"xc"` // Namespace declared for xc.
}

// Extension preserves an additional XML Signature element at the alert root.
type Extension struct {
	XMLName  xml.Name   `json:"name"`                                 // Element name.
	Attr     []xml.Attr `xml:",any,attr" json:"attributes,omitempty"` // Element attributes.
	InnerXML string     `xml:",innerxml" json:"innerXML,omitempty"`   // Raw child content.
}
