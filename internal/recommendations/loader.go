// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package recommendations

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed definitions/**/*.yaml
var embeddedDefinitions embed.FS

// Load reads all embedded YAML rule definition files and returns a populated Registry.
// It returns an error if any file cannot be parsed or if duplicate rule IDs are found.
func Load() (*Registry, error) {
	return loadFrom(embeddedDefinitions)
}

// loadFrom is the internal loader used by Load and tests.
func loadFrom(fsys fs.FS) (*Registry, error) {
	defs := map[string]*Recommendation{}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var rules []Recommendation
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		for i := range rules {
			r := &rules[i]
			if r.ID == "" {
				return fmt.Errorf("rule in %s has an empty id", path)
			}
			if _, exists := defs[r.ID]; exists {
				return fmt.Errorf("duplicate rule id %q found in %s", r.ID, path)
			}
			defs[r.ID] = r
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("loading rule definitions: %w", err)
	}

	return &Registry{defs: defs}, nil
}
