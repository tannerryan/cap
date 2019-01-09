// BSD 2-Clause License
//
// Copyright (c) 2019 Tanner Ryan. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The names "OASIS" and “CAP” are trademarks of OASIS, the owner and developer
// of this specification. Copyright (c) 2010 OASIS. All rights reserved.

package cap

import "encoding/xml"

// Alert provides basic information about the current message: its purpose, its
// source and its status, as well as a unique identifier for the current message
// and links to any other, related messages.  An Alert struct may be used alone
// for message acknowledgements, cancellations or other system functions, but
// most Alert struct will include at least one Info struct.
type Alert struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:emergency:cap:1.2 alert" json:"alert"` // Reference CAP URN (REQUIRED)

	Identifier  string   `xml:"identifier" json:"identifier"`   // Identifier of the alert message (REQUIRED)
	Sender      string   `xml:"sender" json:"sender"`           // Identifier of the sender of the alert message (REQUIRED)
	Sent        DateTime `xml:"sent" json:"sent"`               // Time and date of the origination of the alert message (REQUIRED)
	Status      Status   `xml:"status" json:"status"`           // Code denoting the appropriate handling of the alert message (REQUIRED)
	MsgType     MsgType  `xml:"msgType" json:"msgType"`         // Code denoting the nature of the alert message (REQUIRED)
	Source      string   `xml:"source" json:"source"`           // Text identifying the source of the alert message
	Scope       Scope    `xml:"scope" json:"scope"`             // Code denoting the intended distribution of the alert message (REQUIRED)
	Restriction string   `xml:"restriction" json:"restriction"` // Text describing the rule for limiting the distribution of the restricted alert message (CONDITIONAL)
	Addresses   string   `xml:"addresses" json:"addresses"`     // Group listing of intended recipients of the alert message (CONDITIONAL)
	Code        []string `xml:"code" json:"code"`               // Code denoting special handling of the alert message
	Note        string   `xml:"note" json:"note"`               // Text describing the purpose or significance of the alert message
	References  List     `xml:"references" json:"references"`   // Group listing identifying earlier message(s) reference by the alert message
	Incidents   string   `xml:"incidents" json:"incidents"`     // Group listing naming the referent incident(s) of the alert message

	Info      []Info      `xml:"info" json:"info"`           // Container for all component parts of the info sub-element of the alert message
	Signature []Signature `xml:"Signature" json:"signature"` // Standard XML Digital Signature, not originally defined in CAP, used in CAP-CP and NAADS
}

// Info struct describes an anticipated or actual event in terms of its urgency
// (time available to prepare), severity (intensity of impact) and certainty
// (confidence in the observation or prediction), as well as providing both
// categorical and textual descriptions of the subject event.  It may also
// provide instructions for appropriate response by message recipients and
// various other details (hazard duration, technical parameters, contact
// information, links to additional information sources, etc.)  Multiple Info
// structs may be used to describe differing parameters (e.g., for different
// probability or intensity “bands”) or to provide the information in multiple
// languages.
type Info struct {
	XMLName xml.Name `xml:"info"` // Info CAP

	Language     string         `xml:"language" json:"language"`         // Code denoting the language of the info sub-element of the alert message
	Category     []Category     `xml:"category" json:"category"`         // Code denoting the category of the subject event of the alert message (REQUIRED)
	Event        string         `xml:"event" json:"event"`               // Text denoting the type of the subject event of the alert message (REQUIRED)
	ResponseType []ResponseType `xml:"responseType" json:"responseType"` // Code denoting the type of action recommended for the target audience
	Urgency      Urgency        `xml:"urgency" json:"urgency"`           // Code denoting the urgency of the subject event of the alert message (REQUIRED)
	Severity     Severity       `xml:"severity" json:"severity"`         // Code denoting the severity of the subject event of the alert message (REQUIRED)
	Certainty    Certainty      `xml:"certainty" json:"certainty"`       // Code denoting the certainty of the subject event of the alert message (REQUIRED)
	Audience     string         `xml:"audience" json:"audience"`         // Text describing the intended audience of the alert message
	EventCode    []KeyValue     `xml:"eventCode" json:"eventCode"`       // System-specific code identifying the event type of the alert message
	Effective    DateTime       `xml:"effective" json:"effective"`       // Effective time of the information of the alert message
	Onset        DateTime       `xml:"onset" json:"onset"`               // Expected time of the beginning of the subject event of the alert message
	Expires      DateTime       `xml:"expires" json:"expires"`           // Expiry time of the information of the alert message
	SenderName   string         `xml:"senderName" json:"senderName"`     // Text naming the originator of the alert message
	Headline     string         `xml:"headline" json:"headline"`         // Text headline of the alert message
	Description  string         `xml:"description" json:"description"`   // Text describing the subject event of the alert message
	Instruction  string         `xml:"instruction" json:"instruction"`   // Text describing the recommended action to be taken by recipients of the alert message
	Web          string         `xml:"web" json:"web"`                   // Identifier of the hyperlink associating additional information with the alert message
	Contact      string         `xml:"contact" json:"contact"`           // Text describing the contact for follow-up and confirmation of the alert message
	Parameter    []KeyValue     `xml:"parameter" json:"parameter"`       // System-specific additional parameter associated with the alert message

	Resource []Resource `xml:"resource" json:"resource"` // Container for all component parts of the resource sub-element of the info sub-element of the alert element
	Area     []Area     `xml:"area" json:"area"`         // Container for all component parts of the area sub-element of the info sub-element of the alert message
}

// Resource struct provides an optional reference to additional information
// related to the Info struct within which it appears in the form of a digital
// asset such as an image or audio file.
type Resource struct {
	XMLName xml.Name `xml:"resource" json:"resource"` // Resouce CAP

	ResourceDesc string `xml:"resourceDesc" json:"resourceDesc"` // Text describing the type and content of the resource file (REQUIRED)
	MimeType     string `xml:"mimeType" json:"mimeType"`         // Identifier of the MIME content type and sub-type describing the resource file (REQUIRED)
	Size         int    `xml:"size" json:"size"`                 // Integer indicating the size of the resource file
	URI          string `xml:"uri" json:"uri"`                   // Identifier of the hyperlink for the resource file
	DerefURI     string `xml:"derefUri" json:"derefUri"`         // Base-64 encoded data content of the resource file (CONDITIONAL)
	Digest       string `xml:"digest" json:"digest"`             // Code representing the digital digest ("hash") computed from the resource file

}

// Area struct describes a geographic area to which the Info struct in which it
// appears applies.  Textual and coded descriptions (such as postal codes) are
// supported, but the preferred representations use geospatial shapes (polygons
// and circles) and an altitude or altitude range, expressed in standard
// latitude / longitude / altitude terms in accordance with a specified
// geospatial datum.
type Area struct {
	XMLName xml.Name `xml:"area" json:"area"` // Area CAP

	AreaDesc string     `xml:"areaDesc" json:"areaDesc"` // Text describing the affected area of the alert message (REQUIRED)
	Polygon  List       `xml:"polygon" json:"polygon"`   // Paired values of points defining a polygon that delineates the affected area of the alert message
	Circle   []string   `xml:"circle" json:"circle"`     // Paired values of a point and radius delineating the affected area of the alert message
	Geocode  []KeyValue `xml:"geocode" json:"geocode"`   // Geographic code delineating the affected area of the alert message
	Altitude float32    `xml:"altitude" json:"altitude"` // Specific or minimum altitude of the affected area of the alert message
	Ceiling  float32    `xml:"ceiling" json:"ceiling"`   // Maximum altitude of the affected area of the alert message (CONDITIONAL)
}

// KeyValue is a generic element for representing key-value pairs
type KeyValue struct {
	ValueName string `xml:"valueName" json:"valueName"`
	Value     string `xml:"value" json:"value"`
}

// Signature is a standard XML digital signature. This is not included in the
// original CAP protocol, but is implemented in CAP-CP and is enforced in
// Pelmorex's National Alert Aggregation & Dissemination System (NAADS).
type Signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature" json:"signature"`

	ID                  string              `xml:"Id,attr" json:"id"`
	SignedInfo          SignedInfo          `xml:"SignedInfo" json:"signedInfo"`
	SignatureValue      string              `xml:"SignatureValue" json:"signatureValue"`
	X509Certificate     string              `xml:"KeyInfo>X509Data>X509Certificate" json:"x509Certificate"`
	SignatureProperties []SignatureProperty `xml:"Object>SignatureProperties>SignatureProperty" json:"signatureProperty"`
}

// SignedInfo elements references the signed data and specifies what algorithms
// are used.
type SignedInfo struct {
	CanonicalizationMethod Algorithm `xml:"CanonicalizationMethod" json:"canonicalizationMethod"`
	SignatureMethod        Algorithm `xml:"SignatureMethod" json:"signatureMethod"`
	Reference              Reference `xml:"Reference" json:"reference"`
}

// Reference elements specify the resource being signed by URI reference and any
// transforms to be applied to the resource prior to signing.
type Reference struct {
	URI          string    `xml:"URI,attr" json:"uri"`
	Transform    Algorithm `xml:"Transforms>Transform" json:"transform"`
	DigestMethod Algorithm `xml:"DigestMethod" json:"digestMethod"`
	DigestValue  string    `xml:"DigestValue" json:"digestValue"`
}

// SignatureProperty is the simplified Object element that contains the signed
// data for the enveloping signature.
type SignatureProperty struct {
	ID      string  `xml:"Id,attr" json:"id"`
	Target  string  `xml:"Target,attr" json:"target"`
	XCValue XCValue `xml:"value" json:"value"`
}

// Algorithm is required to access algorithm definitions within the XML digital
// signature specification.
type Algorithm struct {
	Algorithm string `xml:"Algorithm,attr" json:"algorithm"`
}

// XCValue is required to access the value of the SignatureProperty.
type XCValue struct {
	XC string `xml:"xc,attr" json:"xc"`
}

// protocol.go
