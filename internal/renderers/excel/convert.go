// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import "encoding/json"

// asType converts a scan-result value into the desired concrete type.
//
// Live scans store typed pointers (e.g. *scanners.RepositoryData) directly in
// the results map, whereas replays loaded from a previous scan JSON via
// --from-json store map[string]interface{}. This helper handles both shapes by
// returning the value directly when it is already the right pointer type, and
// otherwise falling back to a JSON round-trip. It returns nil when the value is
// nil or cannot be converted.
func asType[T any](v interface{}) *T {
	if v == nil {
		return nil
	}
	if t, ok := v.(*T); ok {
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return &out
}
