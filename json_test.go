// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tannerryan/cap"
)

// TestJSONRoundTrip checks the documented JSON representation.
func TestJSONRoundTrip(t *testing.T) {
	want := validAlert(t)
	want.Info[0].ResponseType = []cap.ResponseType{cap.ResponseTypeMonitor}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("XMLName")) || bytes.Contains(data, []byte(`"alert":{`)) {
		t.Fatalf("XML metadata leaked into JSON: %s", data)
	}
	var got cap.Alert
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sent.String() != want.Sent.String() || got.Status != want.Status {
		t.Fatalf("alert fields changed after JSON round trip: %#v", got)
	}
	if got.Info[0].ResponseType[0] != cap.ResponseTypeMonitor ||
		got.Info[0].Area[0].Polygon[0].String() != want.Info[0].Area[0].Polygon[0].String() {
		t.Fatalf("info fields changed after JSON round trip: %#v", got.Info[0])
	}
}

// TestInvalidEnumJSON checks that unset CAP codes cannot be encoded.
func TestInvalidEnumJSON(t *testing.T) {
	values := []struct {
		name  string
		value any
	}{
		{"category", cap.Category(0)},
		{"certainty", cap.Certainty(0)},
		{"message type", cap.MsgType(0)},
		{"response type", cap.ResponseType(0)},
		{"scope", cap.Scope(0)},
		{"severity", cap.Severity(0)},
		{"status", cap.Status(0)},
		{"urgency", cap.Urgency(0)},
	}
	for _, test := range values {
		t.Run(test.name, func(t *testing.T) {
			if _, err := json.Marshal(test.value); err == nil {
				t.Fatal("expected invalid enum error")
			}
		})
	}
}
