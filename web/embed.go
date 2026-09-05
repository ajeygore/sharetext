// Package web holds the templates, stylesheet and browser scripts, embedded
// into the binary so a deploy is a single file with nothing to copy alongside.
package web

import "embed"

//go:embed templates/*.html
var Templates embed.FS

//go:embed static
var Static embed.FS
