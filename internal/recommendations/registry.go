// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package recommendations

import (
	"slices"
	"strings"
)

// Registry provides read access to the loaded rule definitions.
type Registry struct {
	defs map[string]*Recommendation
}

// sortByID sorts a slice of Recommendations in ascending ID order.
func sortByID(recs []*Recommendation) {
	slices.SortFunc(recs, func(a, b *Recommendation) int {
		return strings.Compare(a.ID, b.ID)
	})
}

// Get returns the Recommendation for the given ID, or false if not found.
func (r *Registry) Get(id string) (*Recommendation, bool) {
	def, ok := r.defs[id]
	return def, ok
}

// filter returns all rule definitions matching predicate, sorted by ID.
func (r *Registry) filter(predicate func(*Recommendation) bool) []*Recommendation {
	var out []*Recommendation
	for _, d := range r.defs {
		if predicate(d) {
			out = append(out, d)
		}
	}
	sortByID(out)
	return out
}

// All returns all registered rule definitions, sorted by ID.
func (r *Registry) All() []*Recommendation {
	return r.filter(func(_ *Recommendation) bool { return true })
}

// ByScope returns all rule definitions for the given scope, sorted by ID.
func (r *Registry) ByScope(scope Scope) []*Recommendation {
	return r.filter(func(d *Recommendation) bool { return d.Scope == scope })
}

// ByCategory returns all rule definitions for the given category, sorted by ID.
func (r *Registry) ByCategory(category string) []*Recommendation {
	return r.filter(func(d *Recommendation) bool { return d.Category == category })
}

// Count returns the total number of registered rules.
func (r *Registry) Count() int {
	return len(r.defs)
}
