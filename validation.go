// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// languagePattern checks CAP language tags.
var languagePattern = regexp.MustCompile(`^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$`)

// DiagnosticLevel says whether a result is an error or warning.
type DiagnosticLevel string

const (
	// DiagnosticError marks a failed rule.
	DiagnosticError DiagnosticLevel = "error"
	// DiagnosticWarning marks a recommendation.
	DiagnosticWarning DiagnosticLevel = "warning"
)

// Diagnostic describes one validation result.
type Diagnostic struct {
	Level   DiagnosticLevel `json:"level"`          // Error or warning.
	Path    string          `json:"path"`           // Related field path.
	Rule    string          `json:"rule,omitempty"` // CAP rule or recommendation.
	Message string          `json:"message"`        // Description of the result.
}

// Error returns the diagnostic message and its field path.
func (d Diagnostic) Error() string {
	if d.Path == "" {
		return d.Message
	}
	return d.Path + ": " + d.Message
}

// Diagnostics holds validation errors and warnings.
type Diagnostics []Diagnostic

// HasErrors reports whether any result is an error.
func (d Diagnostics) HasErrors() bool {
	for _, diagnostic := range d {
		if diagnostic.Level == DiagnosticError {
			return true
		}
	}
	return false
}

// Err returns the validation errors, or nil if there are none.
func (d Diagnostics) Err() error {
	errors := make(Diagnostics, 0, len(d))
	for _, diagnostic := range d {
		if diagnostic.Level == DiagnosticError {
			errors = append(errors, diagnostic)
		}
	}
	if len(errors) == 0 {
		return nil
	}
	return ValidationError{Diagnostics: errors}
}

// ValidationError contains validation errors.
type ValidationError struct {
	Diagnostics Diagnostics // Failed validation rules.
}

// Error returns the first error and the number of additional errors.
func (e ValidationError) Error() string {
	if len(e.Diagnostics) == 0 {
		return "cap: validation failed"
	}
	if len(e.Diagnostics) == 1 {
		return "cap: " + e.Diagnostics[0].Error()
	}
	return fmt.Sprintf("cap: %s (and %d more)", e.Diagnostics[0].Error(), len(e.Diagnostics)-1)
}

// Validate checks the CAP 1.2 rules supported by this package.
func (a *Alert) Validate() Diagnostics {
	var diagnostics Diagnostics
	if a == nil {
		return appendError(diagnostics, "alert", "CAP 1.2", "alert is nil")
	}
	if a.XMLName.Local != "" && (a.XMLName.Local != "alert" || a.XMLName.Space != capNamespace) {
		diagnostics = appendError(diagnostics, "alert", "CAP 1.2", "invalid CAP namespace or root element")
	}
	if strings.TrimSpace(a.Identifier) == "" {
		diagnostics = appendError(diagnostics, "identifier", "CAP 1.2 §3.2.1", "identifier is required")
	} else if hasRestrictedIdentifierCharacter(a.Identifier) {
		diagnostics = appendError(diagnostics, "identifier", "CAP 1.2 §3.2.1", "identifier contains a restricted character")
	}
	if strings.TrimSpace(a.Sender) == "" {
		diagnostics = appendError(diagnostics, "sender", "CAP 1.2 §3.2.1", "sender is required")
	} else if hasRestrictedIdentifierCharacter(a.Sender) {
		diagnostics = appendError(diagnostics, "sender", "CAP 1.2 §3.2.1", "sender contains a restricted character")
	}
	if a.Sent.IsZero() {
		diagnostics = appendError(diagnostics, "sent", "CAP 1.2 §3.2.1", "sent is required")
	}
	if a.Status.String() == "" {
		diagnostics = appendError(diagnostics, "status", "CAP 1.2 §3.2.1", "status is required")
	}
	if a.MsgType.String() == "" {
		diagnostics = appendError(diagnostics, "msgType", "CAP 1.2 §3.2.1", "msgType is required")
	}
	if a.Scope.String() == "" {
		diagnostics = appendError(diagnostics, "scope", "CAP 1.2 §3.2.1", "scope is required")
	}
	if a.Scope == ScopeRestricted && strings.TrimSpace(a.Restriction) == "" {
		diagnostics = appendError(diagnostics, "restriction", "CAP 1.2 §3.2.1", "restriction is required for restricted scope")
	} else if a.Scope != ScopeRestricted && a.Restriction != "" {
		diagnostics = appendError(diagnostics, "restriction", "CAP 1.2 §3.2.1", "restriction is only allowed for restricted scope")
	}
	if a.Scope == ScopePrivate && len(strings.Fields(a.Addresses)) == 0 {
		diagnostics = appendError(diagnostics, "addresses", "CAP 1.2 §3.2.1", "addresses are required for private scope")
	}
	if a.Status == StatusExercise && strings.TrimSpace(a.Note) == "" {
		diagnostics = appendWarning(diagnostics, "note", "CAP 1.2 §3.2.1", "exercise messages should identify the exercise")
	}
	if a.MsgType == MsgTypeError && strings.TrimSpace(a.Note) == "" {
		diagnostics = appendWarning(diagnostics, "note", "CAP 1.2 §3.2.1", "error messages should explain the error")
	}
	if requiresReferences(a.MsgType) && (a.References == nil || len(a.References.val) == 0) {
		diagnostics = appendError(diagnostics, "references", "CAP 1.2 §3.2.1", "references are required for this message type")
	}
	if a.References != nil {
		for i, reference := range a.References.val {
			parts := strings.Split(reference, ",")
			if len(parts) != 3 {
				diagnostics = appendError(diagnostics, fmt.Sprintf("references[%d]", i), "CAP 1.2 §3.2.1", "reference must contain sender, identifier, and sent time")
				continue
			}
			if parts[0] == "" || parts[1] == "" {
				diagnostics = appendError(diagnostics, fmt.Sprintf("references[%d]", i), "CAP 1.2 §3.2.1", "reference sender and identifier cannot be empty")
			} else if hasRestrictedIdentifierCharacter(parts[0]) || hasRestrictedIdentifierCharacter(parts[1]) {
				diagnostics = appendError(diagnostics, fmt.Sprintf("references[%d]", i), "CAP 1.2 §3.2.1", "reference sender or identifier contains a restricted character")
			}
			if _, err := ParseDateTime(parts[2]); err != nil {
				diagnostics = appendError(diagnostics, fmt.Sprintf("references[%d]", i), "CAP 1.2 §3.2.1", "reference has an invalid sent time")
			}
		}
	}
	for i, extension := range a.Extensions {
		if extension.XMLName.Space != xmlSignatureNamespace {
			diagnostics = appendError(diagnostics, fmt.Sprintf("extensions[%d]", i), "CAP 1.2 schema", "root extensions must use the XML Signature namespace")
		}
	}
	if a.MsgType == MsgTypeAlert && len(a.Info) == 0 {
		diagnostics = appendWarning(diagnostics, "info", "CAP 1.2 §1.3", "alerts should include an info block")
	}
	for i := range a.Info {
		diagnostics = validateInfo(diagnostics, &a.Info[i], fmt.Sprintf("info[%d]", i))
		if a.Scope == ScopePublic {
			for j, response := range a.Info[i].ResponseType {
				if response == ResponseTypeAssess {
					diagnostics = appendWarning(diagnostics, fmt.Sprintf("info[%d].responseType[%d]", i, j), "CAP 1.2 §3.2.2", "Assess should not be used for public warnings")
				}
			}
		}
	}
	return diagnostics
}

// validateInfo checks one CAP info block.
func validateInfo(diagnostics Diagnostics, info *Info, path string) Diagnostics {
	language := strings.TrimSpace(info.Language)
	if language != "" && !languagePattern.MatchString(language) {
		diagnostics = appendError(diagnostics, path+".language", "CAP 1.2 §3.2.2", "language has an invalid code")
	}
	if len(info.Category) == 0 {
		diagnostics = appendError(diagnostics, path+".category", "CAP 1.2 §3.2.2", "at least one category is required")
	}
	for i, category := range info.Category {
		if category.String() == "" {
			diagnostics = appendError(diagnostics, fmt.Sprintf("%s.category[%d]", path, i), "CAP 1.2 §3.2.2", "invalid category")
		}
	}
	if strings.TrimSpace(info.Event) == "" {
		diagnostics = appendError(diagnostics, path+".event", "CAP 1.2 §3.2.2", "event is required")
	}
	if info.Urgency.String() == "" {
		diagnostics = appendError(diagnostics, path+".urgency", "CAP 1.2 §3.2.2", "urgency is required")
	}
	if info.Severity.String() == "" {
		diagnostics = appendError(diagnostics, path+".severity", "CAP 1.2 §3.2.2", "severity is required")
	}
	if info.Certainty.String() == "" {
		diagnostics = appendError(diagnostics, path+".certainty", "CAP 1.2 §3.2.2", "certainty is required")
	}
	for i, response := range info.ResponseType {
		if response.String() == "" {
			diagnostics = appendError(diagnostics, fmt.Sprintf("%s.responseType[%d]", path, i), "CAP 1.2 §3.2.2", "invalid response type")
		}
	}
	for i, value := range info.EventCode {
		diagnostics = validateKeyValue(diagnostics, value, fmt.Sprintf("%s.eventCode[%d]", path, i))
	}
	for i, value := range info.Parameter {
		diagnostics = validateKeyValue(diagnostics, value, fmt.Sprintf("%s.parameter[%d]", path, i))
	}
	if info.Web != "" {
		if parsed, err := url.Parse(info.Web); err != nil || !parsed.IsAbs() {
			diagnostics = appendError(diagnostics, path+".web", "CAP 1.2 §3.2.2", "web must be an absolute URI")
		}
	}
	for i := range info.Resource {
		diagnostics = validateResource(diagnostics, &info.Resource[i], fmt.Sprintf("%s.resource[%d]", path, i))
	}
	for i := range info.Area {
		diagnostics = validateArea(diagnostics, &info.Area[i], fmt.Sprintf("%s.area[%d]", path, i))
	}
	return diagnostics
}

// validateResource checks one CAP resource block.
func validateResource(diagnostics Diagnostics, resource *Resource, path string) Diagnostics {
	if strings.TrimSpace(resource.ResourceDesc) == "" {
		diagnostics = appendError(diagnostics, path+".resourceDesc", "CAP 1.2 §3.2.3", "resource description is required")
	}
	if strings.TrimSpace(resource.MimeType) == "" {
		diagnostics = appendError(diagnostics, path+".mimeType", "CAP 1.2 §3.2.3", "MIME type is required")
	} else {
		mediaType, _, err := mime.ParseMediaType(resource.MimeType)
		slash := strings.IndexByte(mediaType, '/')
		if err != nil || slash < 1 || slash == len(mediaType)-1 {
			diagnostics = appendError(diagnostics, path+".mimeType", "CAP 1.2 §3.2.3", "MIME type is invalid")
		}
	}
	if resource.Size != nil && *resource.Size < 0 {
		diagnostics = appendError(diagnostics, path+".size", "CAP 1.2 §3.2.3", "size cannot be negative")
	}
	if resource.URI != "" {
		if parsed, err := url.Parse(resource.URI); err != nil || (!parsed.IsAbs() && resource.DerefURI == "") {
			diagnostics = appendError(diagnostics, path+".uri", "CAP 1.2 §3.2.3", "uri must be absolute unless it names dereferenced content")
		}
	}
	var decodedResource []byte
	derefValid := false
	if resource.DerefURI != "" {
		encoded := strings.Join(strings.Fields(resource.DerefURI), "")
		var err error
		decodedResource, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			diagnostics = appendError(diagnostics, path+".derefUri", "CAP 1.2 §3.2.3", "derefUri must contain base64 data")
		} else {
			derefValid = true
		}
	}
	if resource.Digest != "" {
		digest, ok := decodeSHA1(resource.Digest)
		if !ok {
			diagnostics = appendError(diagnostics, path+".digest", "CAP 1.2 §3.2.3", "digest must contain a base64 or hexadecimal SHA-1 value")
		} else if derefValid {
			sum := sha1.Sum(decodedResource)
			if !bytes.Equal(digest, sum[:]) {
				diagnostics = appendError(diagnostics, path+".digest", "CAP 1.2 §3.2.3", "digest does not match derefUri")
			}
		}
	}
	return diagnostics
}

// validateArea checks one CAP area block.
func validateArea(diagnostics Diagnostics, area *Area, path string) Diagnostics {
	if strings.TrimSpace(area.AreaDesc) == "" {
		diagnostics = appendError(diagnostics, path+".areaDesc", "CAP 1.2 §3.2.4", "area description is required")
	}
	for i, polygon := range area.Polygon {
		polygonPath := fmt.Sprintf("%s.polygon[%d]", path, i)
		points, err := polygon.Coordinates()
		if err != nil {
			diagnostics = appendError(diagnostics, polygonPath, "CAP 1.2 §3.2.4", err.Error())
			continue
		}
		if len(points) < 4 {
			diagnostics = appendError(diagnostics, polygonPath, "CAP 1.2 §3.2.4", "polygon requires at least four coordinate pairs")
		} else if points[0] != points[len(points)-1] {
			diagnostics = appendError(diagnostics, polygonPath, "CAP 1.2 §3.2.4", "polygon must begin and end at the same coordinate")
		}
	}
	for i, circle := range area.Circle {
		if _, err := ParseCircle(circle); err != nil {
			diagnostics = appendError(diagnostics, fmt.Sprintf("%s.circle[%d]", path, i), "CAP 1.2 §3.2.4", err.Error())
		}
	}
	for i, value := range area.Geocode {
		diagnostics = validateKeyValue(diagnostics, value, fmt.Sprintf("%s.geocode[%d]", path, i))
	}
	if len(area.Geocode) > 0 && len(area.Polygon) == 0 && len(area.Circle) == 0 {
		diagnostics = appendWarning(diagnostics, path, "CAP 1.2 §3.2.4", "polygon or circle geometry should accompany geocodes when possible")
	}
	if area.Ceiling != nil && area.Altitude == nil {
		diagnostics = appendError(diagnostics, path+".ceiling", "CAP 1.2 §3.2.4", "ceiling requires altitude")
	}
	altitudeFinite := area.Altitude == nil || (!math.IsNaN(*area.Altitude) && !math.IsInf(*area.Altitude, 0))
	ceilingFinite := area.Ceiling == nil || (!math.IsNaN(*area.Ceiling) && !math.IsInf(*area.Ceiling, 0))
	if !altitudeFinite {
		diagnostics = appendError(diagnostics, path+".altitude", "CAP 1.2 §3.2.4", "altitude must be a finite decimal")
	}
	if !ceilingFinite {
		diagnostics = appendError(diagnostics, path+".ceiling", "CAP 1.2 §3.2.4", "ceiling must be a finite decimal")
	}
	if altitudeFinite && ceilingFinite && area.Altitude != nil && area.Ceiling != nil && *area.Ceiling < *area.Altitude {
		diagnostics = appendError(diagnostics, path+".ceiling", "CAP 1.2 §3.2.4", "ceiling cannot be below altitude")
	}
	return diagnostics
}

// validateKeyValue checks a CAP name and value pair.
func validateKeyValue(diagnostics Diagnostics, value KeyValue, path string) Diagnostics {
	if strings.TrimSpace(value.ValueName) == "" {
		diagnostics = appendError(diagnostics, path+".valueName", "CAP 1.2", "valueName is required")
	}
	if strings.TrimSpace(value.Value) == "" {
		diagnostics = appendError(diagnostics, path+".value", "CAP 1.2", "value is required")
	}
	return diagnostics
}

// requiresReferences reports whether a message must name earlier messages.
func requiresReferences(messageType MsgType) bool {
	return messageType == MsgTypeUpdate || messageType == MsgTypeCancel
}

// hasRestrictedIdentifierCharacter checks CAP sender and identifier values.
func hasRestrictedIdentifierCharacter(value string) bool {
	return strings.ContainsAny(value, ",<&") || strings.IndexFunc(value, unicode.IsSpace) >= 0
}

// decodeSHA1 reads the common text encodings of a SHA-1 digest.
func decodeSHA1(value string) ([]byte, bool) {
	encoded := strings.Join(strings.Fields(value), "")
	if digest, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(digest) == sha1.Size {
		return digest, true
	}
	digest, err := hex.DecodeString(encoded)
	return digest, err == nil && len(digest) == sha1.Size
}

// appendError adds a validation error.
func appendError(diagnostics Diagnostics, path, rule, message string) Diagnostics {
	return append(diagnostics, Diagnostic{Level: DiagnosticError, Path: path, Rule: rule, Message: message})
}

// appendWarning adds a validation warning.
func appendWarning(diagnostics Diagnostics, path, rule, message string) Diagnostics {
	return append(diagnostics, Diagnostic{Level: DiagnosticWarning, Path: path, Rule: rule, Message: message})
}
