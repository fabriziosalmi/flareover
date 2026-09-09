// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package textguard holds the checks that keep untrusted text from becoming an
// instruction.
//
// Both ends of the pipeline need them: the cloudflare package validates a
// decoded snapshot at the boundary, and the ir package validates the plan just
// before a generator renders it — which is the only check that also covers
// values arriving from decisions.lock rather than from the snapshot. Putting
// them here means one implementation rather than two that can drift.
//
// The generators interpolate with a bare %s into a Caddyfile and a BIND zone
// file, both of which are line-oriented interpreters. A newline in a redirect
// target is a new directive; a newline in record content is a new record. There
// is no legitimate Cloudflare configuration value that contains one.
package textguard

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// MaxStringLen bounds any single string carried through the pipeline.
// Cloudflare's own fields are far shorter; this exists so a pathological value
// cannot be carried into a generated configuration file.
const MaxStringLen = 8192

// FindControlStrings walks v and reports every string field that holds a
// control character or exceeds MaxStringLen. path accumulates a readable
// location so the caller's error names the offending field.
//
// The walk is reflective rather than field-by-field on purpose: these structs
// have dozens of nested fields, and a hand-written list stops being complete
// the day somebody adds one.
func FindControlStrings(v any, path string) []string {
	return walk(reflect.ValueOf(v), path)
}

func walk(v reflect.Value, path string) []string {
	var out []string
	switch v.Kind() {
	case reflect.String:
		if bad := checkString(v.String(), path); bad != "" {
			out = append(out, bad)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			out = append(out, walk(v.Field(i), path+"."+t.Field(i).Name)...)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			out = append(out, walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			out = append(out, walk(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k))...)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			out = append(out, walk(v.Elem(), path)...)
		}
	}
	return out
}

func checkString(s, path string) string {
	if len(s) > MaxStringLen {
		return fmt.Sprintf("%s is %d bytes, over the %d-byte limit", path, len(s), MaxStringLen)
	}
	for _, r := range s {
		// Tab is as unwelcome as a newline: a BIND zone line is tab-separated,
		// so an embedded tab shifts every field after it.
		if r == '\n' || r == '\r' || r == '\t' || r == 0 || unicode.IsControl(r) {
			return fmt.Sprintf("%s contains a control character (%q)", path, r)
		}
	}
	return ""
}

// IsHostname reports whether s is a syntactically valid DNS name.
//
// It accepts a leading "*." (Cloudflare wildcard records), a trailing dot, "@"
// for the apex, and underscore labels (_dmarc, _acme-challenge are ubiquitous
// in real zones). It rejects what matters here: path separators, "..", empty
// labels — the shapes that turn a zone name into a directory traversal when it
// is concatenated into an artifact path.
func IsHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	if s == "" || len(s) > 253 {
		return false
	}
	if s == "@" {
		return true
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}
