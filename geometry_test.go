// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"testing"

	"github.com/tannerryan/cap"
)

// TestParseGeometry checks coordinate, polygon, and circle helpers.
func TestParseGeometry(t *testing.T) {
	coordinate, err := cap.ParseCoordinate("45.5,-75.25")
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinate.String(); got != "45.5,-75.25" {
		t.Fatalf("coordinate = %q", got)
	}

	circle, err := cap.ParseCircle("45.5,-75.25 12.5")
	if err != nil {
		t.Fatal(err)
	}
	if circle.Center != coordinate || circle.RadiusKM != 12.5 {
		t.Fatalf("circle = %#v", circle)
	}
	if got := circle.String(); got != "45.5,-75.25 12.5" {
		t.Fatalf("circle string = %q", got)
	}

	area := cap.Area{
		Polygon: []cap.List{cap.NewList("45,-75", "46,-75", "46,-74", "45,-75")},
		Circle:  []string{"45.5,-75.25 12.5"},
	}
	polygons, err := area.Polygons()
	if err != nil {
		t.Fatal(err)
	}
	if len(polygons) != 1 || len(polygons[0]) != 4 {
		t.Fatalf("polygons = %#v", polygons)
	}
	circles, err := area.Circles()
	if err != nil {
		t.Fatal(err)
	}
	if len(circles) != 1 || circles[0] != circle {
		t.Fatalf("circles = %#v", circles)
	}
	for _, value := range []string{"91,0", "0x1p0,0", "1e1,0"} {
		if _, err := cap.ParseCoordinate(value); err == nil {
			t.Fatalf("expected invalid coordinate error for %q", value)
		}
	}
	if _, err := cap.ParseCircle("45,-75 1e2"); err == nil {
		t.Fatal("expected invalid radius error")
	}
}
