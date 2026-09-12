// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/cap"
)

// validAlert returns a valid CAP alert for tests.
func validAlert(t *testing.T) *cap.Alert {
	t.Helper()
	sent, err := cap.ParseDateTime("2026-09-12T12:00:00-05:00")
	if err != nil {
		t.Fatal(err)
	}
	return &cap.Alert{
		Identifier: "example-1",
		Sender:     "sender.example",
		Sent:       sent,
		Status:     cap.StatusTest,
		MsgType:    cap.MsgTypeAlert,
		Scope:      cap.ScopePublic,
		Info: []cap.Info{{
			Category:  []cap.Category{cap.CategoryGeo},
			Event:     "Test event",
			Urgency:   cap.UrgencyUnknown,
			Severity:  cap.SeverityUnknown,
			Certainty: cap.CertaintyUnknown,
			Area: []cap.Area{{
				AreaDesc: "Test area",
				Polygon: []cap.List{cap.NewList(
					"45,-75", "46,-75", "46,-74", "45,-75",
				)},
			}},
		}},
	}
}

// TestValidateCAP checks valid and invalid core fields.
func TestValidateCAP(t *testing.T) {
	alert := validAlert(t)
	if diagnostics := alert.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}

	alert.Status = 0
	alert.Identifier = "bad\tid"
	alert.Info[0].Area[0].Polygon[0] = cap.NewList("45,-75", "46,-75")
	alert.Extensions = []cap.Extension{{XMLName: xml.Name{Space: "urn:example", Local: "extra"}}}
	diagnostics := alert.Validate()
	if !diagnostics.HasErrors() {
		t.Fatal("expected validation errors")
	}
	if !hasDiagnosticPath(diagnostics, "identifier") || !hasDiagnosticPath(diagnostics, "status") || !hasDiagnosticPath(diagnostics, "extensions[0]") ||
		!hasDiagnosticPath(diagnostics, "info[0].area[0].polygon[0]") {
		t.Fatalf("missing expected diagnostic paths: %#v", diagnostics)
	}
}

// TestValidateResourceAndAltitude checks resource and vertical bounds.
func TestValidateResourceAndAltitude(t *testing.T) {
	alert := validAlert(t)
	contents := []byte("resource")
	digest := sha1.Sum(contents)
	size := int64(len(contents))
	altitude := 500.0
	alert.Info[0].Resource = []cap.Resource{{
		ResourceDesc: "Text",
		MimeType:     "text/plain; charset=utf-8",
		Size:         &size,
		DerefURI:     base64.StdEncoding.EncodeToString(contents),
		Digest:       base64.StdEncoding.EncodeToString(digest[:]),
	}}
	alert.Info[0].Area[0].Altitude = &altitude
	if diagnostics := alert.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}
	alert.Info[0].Resource[0].Digest = fmt.Sprintf("%x", digest)
	if diagnostics := alert.Validate(); diagnostics.HasErrors() {
		t.Fatalf("hexadecimal digest failed: %v", diagnostics.Err())
	}

	alert.Info[0].Resource[0].MimeType = "invalid"
	alert.Info[0].Resource[0].Digest = base64.StdEncoding.EncodeToString(make([]byte, sha1.Size))
	invalidAltitude := math.Inf(1)
	alert.Info[0].Area[0].Altitude = &invalidAltitude
	diagnostics := alert.Validate()
	for _, path := range []string{"info[0].resource[0].mimeType", "info[0].resource[0].digest", "info[0].area[0].altitude"} {
		if !hasDiagnosticPath(diagnostics, path) {
			t.Errorf("missing diagnostic for %s: %#v", path, diagnostics)
		}
	}

	alert = validAlert(t)
	altitude = 1000
	ceiling := 500.0
	alert.Info[0].Area[0].Altitude = &altitude
	alert.Info[0].Area[0].Ceiling = &ceiling
	if diagnostics := alert.Validate(); !hasDiagnosticPath(diagnostics, "info[0].area[0].ceiling") {
		t.Fatalf("missing ceiling diagnostic: %#v", diagnostics)
	}
}

// TestValidateReferences checks extended message identifiers.
func TestValidateReferences(t *testing.T) {
	alert := validAlert(t)
	alert.MsgType = cap.MsgTypeUpdate
	references := cap.NewList("sender.example,bad&id,2026-09-12T11:00:00-05:00")
	alert.References = &references
	if diagnostics := alert.Validate(); !hasDiagnosticPath(diagnostics, "references[0]") {
		t.Fatalf("missing reference diagnostic: %#v", diagnostics)
	}
}

// TestValidateAlertConditions checks conditional alert fields and warnings.
func TestValidateAlertConditions(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
		change    func(*cap.Alert)
	}{
		{"restricted scope", "restriction", true, func(alert *cap.Alert) { alert.Scope = cap.ScopeRestricted }},
		{"public restriction", "restriction", true, func(alert *cap.Alert) { alert.Restriction = "internal" }},
		{"private scope", "addresses", true, func(alert *cap.Alert) { alert.Scope = cap.ScopePrivate }},
		{"cancel references", "references", true, func(alert *cap.Alert) { alert.MsgType = cap.MsgTypeCancel }},
		{"exercise note", "note", false, func(alert *cap.Alert) { alert.Status = cap.StatusExercise }},
		{"error note", "note", false, func(alert *cap.Alert) { alert.MsgType = cap.MsgTypeError }},
		{"public assess", "info[0].responseType[0]", false, func(alert *cap.Alert) {
			alert.Info[0].ResponseType = []cap.ResponseType{cap.ResponseTypeAssess}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alert := validAlert(t)
			test.change(alert)
			diagnostics := alert.Validate()
			if !hasDiagnosticPath(diagnostics, test.path) {
				t.Fatalf("missing diagnostic for %s: %#v", test.path, diagnostics)
			}
			if diagnostics.HasErrors() != test.wantError {
				t.Fatalf("HasErrors() = %t, want %t", diagnostics.HasErrors(), test.wantError)
			}
		})
	}
}

// TestParseDeprecatedCertainty checks the CAP 1.0 compatibility value.
func TestParseDeprecatedCertainty(t *testing.T) {
	data, err := cap.MarshalCAP(validAlert(t))
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "<certainty>Unknown</certainty>", "<certainty>Very Likely</certainty>", 1))
	alert, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	if alert.Info[0].Certainty != cap.CertaintyLikely {
		t.Fatalf("certainty = %q", alert.Info[0].Certainty.String())
	}
}

// TestDateTime checks CAP date-time parsing and construction.
func TestDateTime(t *testing.T) {
	for _, value := range []string{
		"2026-09-12T12:00:00+00:00",
		"2026-09-12T12:00:00+14:01",
		"2026-09-12T12:00:00-15:00",
		"2026-09-12T12:00:00.123-05:00",
		"2026-09-12T12:00:00,123-05:00",
		"0000-09-12T12:00:00-05:00",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := cap.ParseDateTime(value); err == nil {
				t.Fatal("expected invalid date-time error")
			}
		})
	}

	value, err := cap.ParseDateTime("2026-09-12T12:00:00+14:00")
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "2026-09-12T12:00:00+14:00" {
		t.Fatalf("date-time = %q", value.String())
	}
	value, err = cap.ParseDateTime("  2026-09-12T12:00:00-05:00\n")
	if err != nil || value.String() != "2026-09-12T12:00:00-05:00" {
		t.Fatalf("trimmed date-time = %q, %v", value.String(), err)
	}

	constructed, err := cap.NewDateTime(time.Date(2026, 9, 12, 12, 0, 0, 0, time.FixedZone("test", -5*60*60)))
	if err != nil {
		t.Fatal(err)
	}
	if constructed.String() != "2026-09-12T12:00:00-05:00" {
		t.Fatalf("constructed date-time = %q", constructed.String())
	}
	if _, err := cap.NewDateTime(time.Date(2026, 9, 12, 12, 0, 0, 0, time.FixedZone("invalid", 15*60*60))); err == nil {
		t.Fatal("expected constructor offset error")
	}
	if _, err := cap.NewDateTime(time.Date(2026, 9, 12, 12, 0, 0, 1, time.UTC)); err == nil {
		t.Fatal("expected constructor precision error")
	}
}

// TestDiagnosticErrors checks validation error formatting.
func TestDiagnosticErrors(t *testing.T) {
	diagnostic := cap.Diagnostic{Level: cap.DiagnosticError, Path: "sender", Message: "sender is invalid"}
	if got := diagnostic.Error(); got != "sender: sender is invalid" {
		t.Fatalf("diagnostic error = %q", got)
	}
	diagnostics := cap.Diagnostics{diagnostic, {Level: cap.DiagnosticError, Path: "scope", Message: "scope is invalid"}}
	if got := diagnostics.Err().Error(); !strings.Contains(got, "and 1 more") {
		t.Fatalf("validation error = %q", got)
	}
}

// TestValidateCAPFixtures checks all bundled XML examples.
func TestValidateCAPFixtures(t *testing.T) {
	files := []string{
		"testing/Oasis_HomelandAlert.xml",
		"testing/Oasis_ThunderstormWarning.xml",
		"testing/Oasis_EarthquakeReport.xml",
		"testing/Oasis_AmberAlert.xml",
		"testing/PelmorexNAADS_WindWarning.xml",
		"testing/PelmorexNAADS_NoAttachment.xml",
		"testing/PelmorexNAADS_ExternalAudioResource.xml",
		"testing/PelmorexNAADS_MultipleExternalResources.xml",
		"testing/PelmorexNAADS_FreehandPolygon.xml",
		"testing/PelmorexNAADS_FreehandCircle.xml",
		"testing/PelmorexNAADS_EventLocation.xml",
		"testing/PelmorexNAADS_MinorChangeParameter.xml",
		"testing/PelmorexNAADS_TextToSpeechResource.xml",
		"testing/PelmorexNAADS_WPASTextParameter.xml",
		"testing/NWS_TornadoWarning.xml",
		"testing/NWS_TornadoWarningUpdate.xml",
		"testing/NWS_FlashFloodWarning.xml",
		"testing/NWS_HydrologicOutlook.xml",
		"testing/NWS_MarineWeatherStatement.xml",
		"testing/NWS_BeachHazardsStatement.xml",
		"testing/NWS_CoastalFloodAdvisory.xml",
		"testing/NWS_FireWeatherWatchCancel.xml",
		"testing/NWS_GaleWarning.xml",
		"testing/NWS_HeatAdvisory.xml",
		"testing/NWS_RedFlagWarning.xml",
		"testing/NWS_SevereThunderstormWarning.xml",
		"testing/ECCC_WeatherWarning.xml",
		"testing/ECCC_AirQualityAlert.xml",
		"testing/ECCC_FrostAlert.xml",
		"testing/ECCC_SpecialMarineAlert.xml",
		"testing/ECCC_SquallAlert.xml",
		"testing/ECCC_StormSurgeAlert.xml",
		"testing/ECCC_WindAlert.xml",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			alert := parseFixture(t, file)
			if diagnostics := alert.Validate(); diagnostics.HasErrors() {
				t.Fatal(diagnostics.Err())
			}
		})
	}
}

// TestValidationWarningsDoNotReturnAnError checks warning handling.
func TestValidationWarningsDoNotReturnAnError(t *testing.T) {
	alert := validAlert(t)
	alert.Info[0].Area[0].Polygon = nil
	alert.Info[0].Area[0].Geocode = []cap.KeyValue{{
		ValueName: "SAME",
		Value:     "001001",
	}}
	diagnostics := alert.Validate()
	if diagnostics.HasErrors() || diagnostics.Err() != nil {
		t.Fatalf("warning returned as an error: %#v", diagnostics)
	}
	if len(diagnostics) == 0 {
		t.Fatal("expected a geometry recommendation")
	}
}

// TestInfoDefaults checks the language and effective-time defaults.
func TestInfoDefaults(t *testing.T) {
	alert := validAlert(t)
	info := alert.Info[0]
	if got := info.LanguageCode(); got != "en-US" {
		t.Fatalf("LanguageCode() = %q", got)
	}
	info.Language = "  en-CA  "
	if got := info.LanguageCode(); got != "en-CA" {
		t.Fatalf("LanguageCode() = %q", got)
	}
	alert.Info[0].Language = info.Language
	if diagnostics := alert.Validate(); diagnostics.HasErrors() {
		t.Fatalf("trimmed language failed: %v", diagnostics.Err())
	}
	if got := info.EffectiveTime(alert.Sent).Time(); !got.Equal(alert.Sent.Time()) {
		t.Fatalf("EffectiveTime() = %v", got)
	}
	if alert.Sent.Time().Location() == time.UTC {
		t.Fatal("test sent time unexpectedly lost its offset")
	}
}

// hasDiagnosticPath reports whether a field has a validation result.
func hasDiagnosticPath(diagnostics cap.Diagnostics, path string) bool {
	for _, diagnostic := range diagnostics {
		if strings.HasPrefix(diagnostic.Path, path) {
			return true
		}
	}
	return false
}
