// Copyright (c) 2019 Tanner Ryan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package cap is the Go implementation of OASIS Common Alerting Protocol Version
1.2 (CAP) + Canadian Profile (CAP-CP).

Usage

The cap package exposes the function `ParseCAP`. This takes a valid XML CAP 1.2
message as `[]byte` and returns an `Alert` struct. All fields defined within the
Common Alerting Protocol are present in `Alert`. If the XML data is not valid,
an error will be returned.

Here is a simple example of reading the alert headline.

    package main

    import (
        "fmt"
        "io/ioutil"

        "github.com/thetannerryan/cap"
    )

    func main() {
        contents, _ := ioutil.ReadFile("alert.xml")
        alert, err := cap.ParseCAP(contents)
        if err != nil {
            panic(err)
        }
        // print the alert headline
        fmt.Println(alert.Info[0].Headline)
    }

License

Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code is
governed by a BSD-style license that can be found in the LICENSE file.

The names "OASIS" and “CAP” are trademarks of OASIS, the owner and developer of
this specification. Copyright (c) 2010 OASIS. All rights reserved.

*/
package cap
