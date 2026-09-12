// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// decimalPattern checks the decimal form used by CAP geometry values.
var decimalPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$`)

// Coordinate is a WGS 84 latitude and longitude pair.
type Coordinate struct {
	Latitude  float64 // Degrees north or south.
	Longitude float64 // Degrees east or west.
}

// ParseCoordinate parses a CAP latitude,longitude pair.
func ParseCoordinate(value string) (Coordinate, error) {
	latitude, longitude, ok := strings.Cut(strings.TrimSpace(value), ",")
	if !ok {
		return Coordinate{}, fmt.Errorf("cap: invalid coordinate %q", value)
	}
	lat, err := strconv.ParseFloat(latitude, 64)
	if !decimalPattern.MatchString(latitude) || err != nil || math.IsNaN(lat) || math.IsInf(lat, 0) || lat < -90 || lat > 90 {
		return Coordinate{}, fmt.Errorf("cap: invalid latitude %q", latitude)
	}
	lon, err := strconv.ParseFloat(longitude, 64)
	if !decimalPattern.MatchString(longitude) || err != nil || math.IsNaN(lon) || math.IsInf(lon, 0) || lon < -180 || lon > 180 {
		return Coordinate{}, fmt.Errorf("cap: invalid longitude %q", longitude)
	}
	return Coordinate{Latitude: lat, Longitude: lon}, nil
}

// String returns a CAP latitude,longitude pair.
func (c Coordinate) String() string {
	return strconv.FormatFloat(c.Latitude, 'f', -1, 64) + "," +
		strconv.FormatFloat(c.Longitude, 'f', -1, 64)
}

// Coordinates parses the list as a sequence of coordinates.
func (t List) Coordinates() ([]Coordinate, error) {
	coordinates := make([]Coordinate, len(t.val))
	for i, value := range t.val {
		coordinate, err := ParseCoordinate(value)
		if err != nil {
			return nil, fmt.Errorf("coordinate[%d]: %w", i, err)
		}
		coordinates[i] = coordinate
	}
	return coordinates, nil
}

// CircleGeometry is a CAP circle center and radius in kilometers.
type CircleGeometry struct {
	Center   Coordinate // Center point.
	RadiusKM float64    // Radius in kilometers.
}

// String returns a CAP circle value.
func (c CircleGeometry) String() string {
	return c.Center.String() + " " + strconv.FormatFloat(c.RadiusKM, 'f', -1, 64)
}

// ParseCircle parses a CAP circle value.
func ParseCircle(value string) (CircleGeometry, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return CircleGeometry{}, fmt.Errorf("cap: invalid circle %q", value)
	}
	center, err := ParseCoordinate(parts[0])
	if err != nil {
		return CircleGeometry{}, err
	}
	radius, err := strconv.ParseFloat(parts[1], 64)
	if !decimalPattern.MatchString(parts[1]) || err != nil || math.IsNaN(radius) || math.IsInf(radius, 0) || radius < 0 {
		return CircleGeometry{}, fmt.Errorf("cap: invalid radius %q", parts[1])
	}
	return CircleGeometry{Center: center, RadiusKM: radius}, nil
}

// Polygons returns the parsed polygon coordinates in the area.
func (a Area) Polygons() ([][]Coordinate, error) {
	polygons := make([][]Coordinate, len(a.Polygon))
	for i, polygon := range a.Polygon {
		coordinates, err := polygon.Coordinates()
		if err != nil {
			return nil, fmt.Errorf("polygon[%d]: %w", i, err)
		}
		polygons[i] = coordinates
	}
	return polygons, nil
}

// Circles returns the parsed circles in the area.
func (a Area) Circles() ([]CircleGeometry, error) {
	circles := make([]CircleGeometry, len(a.Circle))
	for i, value := range a.Circle {
		circle, err := ParseCircle(value)
		if err != nil {
			return nil, fmt.Errorf("circle[%d]: %w", i, err)
		}
		circles[i] = circle
	}
	return circles, nil
}
