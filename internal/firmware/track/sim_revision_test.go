package track

import (
	"context"
	"fmt"
)

// catalogOf is the catalog pkg caches for the folder the box's repository file
// points at.
func (d *simDevice) catalogOf() (Catalog, error) {
	cat, ok := d.folderOf()
	if !ok {
		return Catalog{}, fmt.Errorf("no catalog")
	}
	sum := func(name, version string) string { return name + "@" + version + d.catalogSalt }
	records := []CatalogRecord{
		{"opnsense", cat.core, sum("opnsense", cat.core)},
		{"opnsense-update", cat.update, sum("opnsense-update", cat.update)},
	}
	for name, version := range cat.pkgs {
		records = append(records, CatalogRecord{name, version, sum(name, version)})
	}
	return NewCatalog(records)
}

func (d *simDevice) Catalog(context.Context) (Catalog, error) {
	d.mu.Lock()
	d.catalogReads++
	n, hook := d.catalogReads, d.onCatalogRead
	d.mu.Unlock()
	if hook != nil {
		hook(d, n)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record("catalog")
	if d.catalogErr != nil {
		return Catalog{}, d.catalogErr
	}
	return d.catalogOf()
}

// fingerprint is the revision of the folder the box sees now.
func (d *simDevice) fingerprint() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	cat, err := d.catalogOf()
	if err != nil {
		d.t.Fatalf("catalog: %v", err)
	}
	return cat.Fingerprint
}

// rewrite changes the folder's content in place.
func (d *simDevice) rewrite(salt string) {
	d.mu.Lock()
	d.catalogSalt = salt
	d.mu.Unlock()
}

func advanceWith(approved map[string]string, revisions map[string]string) Payload {
	p := advancePayload(TrackFast, true, approved)
	p.Revisions = revisions
	return p
}
