// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"strings"
	"testing"

	"github.com/tannerryan/cap"
)

// TestValidateCAPCP checks a valid CAP-CP alert and value-name casing.
func TestValidateCAPCP(t *testing.T) {
	alert := validCAPCPAlert(t)
	if diagnostics := alert.ValidateCAPCP(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}

	alert.Info[0].EventCode = append(alert.Info[0].EventCode, cap.KeyValue{
		ValueName: "profile:CAP-CP:Event:0.4",
		Value:     "TESTEVENT",
	})
	if diagnostics := alert.ValidateCAPCP(); diagnostics.HasErrors() {
		t.Fatalf("compatible event code versions failed: %v", diagnostics.Err())
	}
	alert.Info[0].EventCode[0].ValueName = "PROFILE:cap-cp:event:1.0"
	if diagnostics := alert.ValidateCAPCP(); diagnostics.HasErrors() {
		t.Fatalf("case-insensitive event valueName failed: %v", diagnostics.Err())
	}
	alert.Info[0].Area[0].Polygon = nil
	alert.Info[0].Area[0].Geocode = []cap.KeyValue{{
		ValueName: "PROFILE:cap-cp:location:1.0",
		Value:     "1234",
	}}
	if diagnostics := alert.ValidateCAPCP(); diagnostics.HasErrors() {
		t.Fatalf("case-insensitive location valueName failed: %v", diagnostics.Err())
	}

	alert.Info[0].Language = ""
	if diagnostics := alert.ValidateCAPCP(); !hasDiagnosticPath(diagnostics, "info[0].language") {
		t.Fatalf("missing language diagnostic: %#v", diagnostics)
	}
}

// TestValidateCAPCPRules checks CAP-CP rules with invalid inputs.
func TestValidateCAPCPRules(t *testing.T) {
	tests := []struct {
		name   string
		rule   string
		change func(*cap.Alert)
	}{
		{"profile code", "CAP-CP rule 3", func(alert *cap.Alert) { alert.Code = nil }},
		{"public info", "CAP-CP rule 4", func(alert *cap.Alert) { alert.Info = nil }},
		{"subject event", "CAP-CP rule 2", func(alert *cap.Alert) {
			other := alert.Info[0]
			other.EventCode = []cap.KeyValue{{ValueName: "profile:CAP-CP:Event:1.0", Value: "otherEvent"}}
			alert.Info = append(alert.Info, other)
		}},
		{"event code", "CAP-CP rule 6", func(alert *cap.Alert) { alert.Info[0].EventCode = nil }},
		{"location", "CAP-CP rule 7", func(alert *cap.Alert) {
			alert.Info[0].Area[0].Polygon = nil
		}},
		{"area", "CAP-CP rule 8", func(alert *cap.Alert) { alert.Info[0].Area = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alert := validCAPCPAlert(t)
			test.change(alert)
			if diagnostics := alert.ValidateCAPCP(); !hasDiagnosticRule(diagnostics, test.rule) {
				t.Fatalf("missing %s diagnostic: %#v", test.rule, diagnostics)
			}
		})
	}
}

// TestValidateCAPCPMultilingualContent checks language block consistency.
func TestValidateCAPCPMultilingualContent(t *testing.T) {
	alert := validCAPCPAlert(t)
	french := alert.Info[0]
	french.Language = "fr-CA"
	french.Event = "Événement test"
	french.SenderName = "Autorité"
	french.Parameter = []cap.KeyValue{{
		ValueName: "profile:CAP-CP:1.0:AutoTranslated",
		Value:     "yes",
	}}
	french.Area = append([]cap.Area(nil), french.Area...)
	french.Area[0].AreaDesc = "Zone test"
	alert.Info = append(alert.Info, french)
	if diagnostics := alert.ValidateCAPCP(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}

	alert.Info[1].Severity = cap.SeverityMinor
	diagnostics := alert.ValidateCAPCP()
	if !hasDiagnosticRule(diagnostics, "CAP-CP rule 5") {
		t.Fatalf("missing multilingual content diagnostic: %#v", diagnostics)
	}
}

// TestValidateCAPCPRecommendations checks profile recommendation warnings.
func TestValidateCAPCPRecommendations(t *testing.T) {
	alert := validCAPCPAlert(t)
	alert.Info[0].Instruction = "Follow local instructions"
	alert.Info[0].ResponseType = nil
	alert.Info[0].Parameter = []cap.KeyValue{
		{ValueName: "PROFILE:cap-cp:1.0:minorchange", Value: "other"},
		{ValueName: "PROFILE:cap-cp:1.0:autotranslated", Value: "unknown"},
	}
	diagnostics := alert.ValidateCAPCP()
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}
	for _, rule := range []string{"CAP-CP recommendation 5", "CAP-CP recommendation 6", "CAP-CP recommendation 7"} {
		if !hasDiagnosticRule(diagnostics, rule) {
			t.Errorf("missing %s diagnostic: %#v", rule, diagnostics)
		}
	}
}

// TestValidateCAPCPMultipleMinorChanges checks repeated change categories.
func TestValidateCAPCPMultipleMinorChanges(t *testing.T) {
	alert := validCAPCPAlert(t)
	alert.MsgType = cap.MsgTypeUpdate
	references := cap.NewList("sender.example,example-0,2026-09-12T11:00:00-05:00")
	alert.References = &references
	alert.Info[0].Parameter = []cap.KeyValue{
		{ValueName: "profile:CAP-CP:1.0:MinorChange", Value: "correction"},
		{ValueName: "profile:CAP-CP:1.0:MinorChange", Value: "resource"},
	}
	for _, diagnostic := range alert.ValidateCAPCP() {
		if diagnostic.Rule == "CAP-CP recommendation 7" {
			t.Fatalf("unexpected MinorChange diagnostic: %v", diagnostic)
		}
	}
}

// validCAPCPAlert returns a valid alert for profile tests.
func validCAPCPAlert(t *testing.T) *cap.Alert {
	t.Helper()
	alert := validAlert(t)
	alert.Code = []string{"profile:CAP-CP:1.0"}
	alert.Info[0].Language = "en-CA"
	alert.Info[0].SenderName = "Example Authority"
	alert.Info[0].EventCode = []cap.KeyValue{{
		ValueName: "profile:CAP-CP:Event:1.0",
		Value:     "testEvent",
	}}
	return alert
}

// hasDiagnosticRule reports whether a profile rule was returned.
func hasDiagnosticRule(diagnostics cap.Diagnostics, rule string) bool {
	for _, diagnostic := range diagnostics {
		if strings.EqualFold(diagnostic.Rule, rule) {
			return true
		}
	}
	return false
}
