# cap

[![Go
Reference](https://pkg.go.dev/badge/github.com/tannerryan/cap.svg)](https://pkg.go.dev/github.com/tannerryan/cap)
[![License](https://img.shields.io/github/license/tannerryan/cap.svg)](LICENSE)

A Go implementation of [OASIS Common Alerting Protocol Version
1.2](https://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2-os.html) and the
[Canadian Profile
(CAP-CP)](https://www.publicsafety.gc.ca/cnt/rsrcs/pblctns/capcp-ntro-rl-st/index5-en.aspx).

Go 1.27 or newer is required.

The package provides XML parsing and encoding, JSON encoding, CAP 1.2
validation, CAP-CP 1.0 single-message validation, geometry helpers, XML
Signature parsing, and enveloped signature verification.

## Usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/tannerryan/cap"
)

func main() {
	contents, err := os.ReadFile("alert.xml")
	if err != nil {
		panic(err)
	}
	alert, err := cap.ParseCAP(contents)
	if err != nil {
		panic(err)
	}
	if err := alert.Validate().Err(); err != nil {
		panic(err)
	}
	for _, info := range alert.Info {
		fmt.Println(info.Headline)
	}
}
```

`ParseCAP` checks XML syntax, namespaces, dates, and code values. Call
`Validate` for semantic CAP checks. Use `ValidateCAPCP` for the Canadian
profile, `MarshalCAP` to encode an alert, and `VerifySignature` with trusted
certificate roots to check a signed message. Validation returns errors for
broken rules and warnings for recommendations. CAP-CP validation does not
download its separately managed event and location lists or message history.

## Development

Install the development tools with `make deps`, then run `make check`.

## License

This project is available under the [BSD 2-Clause License](LICENSE).
