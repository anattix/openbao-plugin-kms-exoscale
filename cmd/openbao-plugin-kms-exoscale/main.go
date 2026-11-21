// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package main

import "github.com/openbao/go-kms-wrapping/plugin/v2"

func main() {
	plugin.Serve(serveOptions())
}
