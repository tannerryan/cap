// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// capcpEventName matches versioned CAP-CP event value names.
	capcpEventName = regexp.MustCompile(`(?i)^profile:CAP-CP:Event:[0-9]+(?:\.[0-9]+)*$`)
	// capcpLocationName matches versioned CAP-CP location value names.
	capcpLocationName = regexp.MustCompile(`(?i)^profile:CAP-CP:Location:[0-9]+(?:\.[0-9]+)*$`)
)

// ValidateCAPCP checks CAP-CP 1.0 rules that can be determined from one
// message. It does not verify external event and location lists or the
// completeness of active message references. It also checks CAP 1.2.
func (a *Alert) ValidateCAPCP() Diagnostics {
	diagnostics := a.Validate()
	if a == nil {
		return diagnostics
	}
	if !contains(a.Code, "profile:CAP-CP:1.0") {
		diagnostics = appendError(diagnostics, "code", "CAP-CP rule 3", "profile:CAP-CP:1.0 is required")
	}
	if a.Scope == ScopePublic && (a.MsgType == MsgTypeAlert || a.MsgType == MsgTypeUpdate || a.MsgType == MsgTypeCancel) && len(a.Info) == 0 {
		diagnostics = appendError(diagnostics, "info", "CAP-CP rule 4", "an info block is required for public distribution")
	}
	var subjectCode string
	minorChangeBlocks := 0
	for i := range a.Info {
		info := &a.Info[i]
		path := fmt.Sprintf("info[%d]", i)
		if strings.TrimSpace(info.Language) == "" {
			diagnostics = appendError(diagnostics, path+".language", "CAP-CP rule 5", "language is required")
		}
		if strings.TrimSpace(info.SenderName) == "" {
			diagnostics = appendWarning(diagnostics, path+".senderName", "CAP-CP recommendation 4", "senderName is strongly recommended")
		}
		if len(info.ResponseType) == 0 && strings.TrimSpace(info.Instruction) != "" {
			diagnostics = appendWarning(diagnostics, path+".responseType", "CAP-CP recommendation 5", "responseType is recommended when instructions are present")
		}
		autoTranslatedCount := 0
		minorChange := false
		for j, parameter := range info.Parameter {
			parameterPath := fmt.Sprintf("%s.parameter[%d].value", path, j)
			switch strings.ToLower(parameter.ValueName) {
			case "profile:cap-cp:1.0:autotranslated":
				autoTranslatedCount++
				if !equalFoldAny(parameter.Value, "yes", "no") {
					diagnostics = appendWarning(diagnostics, parameterPath, "CAP-CP recommendation 6", "AutoTranslated should be yes or no")
				}
			case "profile:cap-cp:1.0:minorchange":
				minorChange = true
				if !equalFoldAny(parameter.Value, "none", "text", "correction", "resource", "layer", "other") {
					diagnostics = appendWarning(diagnostics, parameterPath, "CAP-CP recommendation 7", "MinorChange has an unrecognized value")
				}
				if a.MsgType != MsgTypeUpdate || a.References == nil || len(a.References.val) == 0 {
					diagnostics = appendWarning(diagnostics, parameterPath, "CAP-CP recommendation 7", "MinorChange is only used on updates with references")
				}
				if strings.EqualFold(parameter.Value, "other") && strings.TrimSpace(a.Note) == "" {
					diagnostics = appendWarning(diagnostics, "note", "CAP-CP recommendation 7", "other minor changes should be explained in note")
				}
			}
		}
		if autoTranslatedCount > 1 {
			diagnostics = appendWarning(diagnostics, path+".parameter", "CAP-CP recommendation 6", "AutoTranslated should occur at most once")
		}
		if minorChange {
			minorChangeBlocks++
		}
		codeCount := 0
		for j, eventCode := range info.EventCode {
			if !strings.HasPrefix(strings.ToLower(eventCode.ValueName), "profile:cap-cp:event:") {
				continue
			}
			codeCount++
			if !capcpEventName.MatchString(eventCode.ValueName) {
				diagnostics = appendError(diagnostics, fmt.Sprintf("%s.eventCode[%d].valueName", path, j), "CAP-CP rule 6", "CAP-CP event code has an invalid valueName")
			}
			if count := utf8.RuneCountInString(eventCode.Value); count < 4 || count > 12 || strings.IndexFunc(eventCode.Value, unicode.IsSpace) >= 0 {
				diagnostics = appendError(diagnostics, fmt.Sprintf("%s.eventCode[%d].value", path, j), "CAP-CP rule 6", "CAP-CP event code must contain 4 to 12 non-space characters")
			}
			if subjectCode == "" {
				subjectCode = strings.ToLower(eventCode.Value)
			} else if !strings.EqualFold(subjectCode, eventCode.Value) {
				diagnostics = appendError(diagnostics, fmt.Sprintf("%s.eventCode[%d].value", path, j), "CAP-CP rule 2", "all info blocks must describe one subject event")
			}
		}
		if codeCount == 0 {
			diagnostics = appendError(diagnostics, path+".eventCode", "CAP-CP rule 6", "a CAP-CP event code is required")
		}
		if len(info.Area) == 0 {
			diagnostics = appendError(diagnostics, path+".area", "CAP-CP rule 8", "an area block is required")
		}
		for j, area := range info.Area {
			areaPath := fmt.Sprintf("%s.area[%d]", path, j)
			if len(area.Polygon) == 0 && len(area.Circle) == 0 && len(area.Geocode) == 0 {
				diagnostics = appendError(diagnostics, areaPath, "CAP-CP rule 7", "a polygon, circle, or geocode is required")
			}
			if len(area.Polygon) == 0 && len(area.Circle) == 0 && len(area.Geocode) > 0 {
				locationCode := false
				for _, geocode := range area.Geocode {
					locationCode = locationCode || capcpLocationName.MatchString(geocode.ValueName)
				}
				if !locationCode {
					diagnostics = appendError(diagnostics, areaPath+".geocode", "CAP-CP rule 7", "a CAP-CP location geocode is required when no geometry is present")
				}
			}
		}
	}
	if minorChangeBlocks > 0 && minorChangeBlocks != len(a.Info) {
		diagnostics = appendWarning(diagnostics, "info", "CAP-CP recommendation 7", "MinorChange should appear in every info block")
	}
	diagnostics = validateCAPCPLanguages(diagnostics, a.Info)
	return diagnostics
}

// validateCAPCPLanguages checks technical content shared by language variants.
func validateCAPCPLanguages(diagnostics Diagnostics, infos []Info) Diagnostics {
	contentByLanguage := make(map[string]map[string]int)
	var languages []string
	for i := range infos {
		language := strings.ToLower(strings.TrimSpace(infos[i].Language))
		if language == "" {
			continue
		}
		if contentByLanguage[language] == nil {
			contentByLanguage[language] = make(map[string]int)
			languages = append(languages, language)
		}
		contentByLanguage[language][capcpTechnicalKey(&infos[i])]++
	}
	if len(languages) < 2 {
		return diagnostics
	}
	baseline := contentByLanguage[languages[0]]
	for _, language := range languages[1:] {
		if !maps.Equal(baseline, contentByLanguage[language]) {
			return appendError(diagnostics, "info", "CAP-CP rule 5", "non-free-form content must match across languages")
		}
	}
	return diagnostics
}

// capcpTechnicalKey returns the content that must match across languages.
func capcpTechnicalKey(info *Info) string {
	type technicalArea struct {
		Polygon  []List
		Circle   []string
		Geocode  []KeyValue
		Altitude *float64
		Ceiling  *float64
	}
	areas := make([]technicalArea, len(info.Area))
	for i := range info.Area {
		areas[i] = technicalArea{
			Polygon:  info.Area[i].Polygon,
			Circle:   info.Area[i].Circle,
			Geocode:  info.Area[i].Geocode,
			Altitude: info.Area[i].Altitude,
			Ceiling:  info.Area[i].Ceiling,
		}
	}
	content := struct {
		Category     []Category
		ResponseType []ResponseType
		Urgency      Urgency
		Severity     Severity
		Certainty    Certainty
		EventCode    []KeyValue
		Effective    *DateTime
		Onset        *DateTime
		Expires      *DateTime
		Area         []technicalArea
	}{
		Category:     info.Category,
		ResponseType: info.ResponseType,
		Urgency:      info.Urgency,
		Severity:     info.Severity,
		Certainty:    info.Certainty,
		EventCode:    info.EventCode,
		Effective:    info.Effective,
		Onset:        info.Onset,
		Expires:      info.Expires,
		Area:         areas,
	}
	encoded, _ := json.Marshal(content)
	return string(encoded)
}

// contains reports whether a string appears in a list.
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// equalFoldAny compares a value with a list without regard to letter case.
func equalFoldAny(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}
