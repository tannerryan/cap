// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tannerryan/cap"
)

// FuzzParseCAP checks that parsing and validation remain safe for arbitrary
// XML.
func FuzzParseCAP(f *testing.F) {
	files, err := filepath.Glob("testing/*.xml")
	if err != nil {
		f.Fatal(err)
	}
	for _, file := range files {
		seed, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		alert, err := cap.ParseCAP(data)
		if err != nil {
			return
		}
		diagnostics := alert.Validate()
		alert.ValidateCAPCP()
		if diagnostics.HasErrors() {
			return
		}
		if _, err := cap.MarshalCAP(alert); err != nil {
			t.Fatalf("marshal parsed alert: %v", err)
		}
	})
}
