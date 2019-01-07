// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cap

import (
	"encoding/xml"
)

// ParseCAP takes a valid XML byte CAP 1.2 message and returns an Alert. If the
// message is invalid, an error will be returned.
func ParseCAP(data []byte) (*Alert, error) {
	var alert Alert
	err := xml.Unmarshal(data, &alert)
	if err != nil {
		return nil, err
	}
	return &alert, nil
}
