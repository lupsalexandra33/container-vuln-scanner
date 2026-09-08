package correlate

import "github.com/lupsalexandra33/container-vuln-scanner/pkg/model"

// aliasGraph groups vulnerability identifiers that refer to the same
// vulnerability.
//
// Scanners lead with different identifier schemes for the same issue. Grype may
// report CVE-2023-45853 carrying GHSA-abcd-efgh-ijkl as an alias, while
// OSV-Scanner reports the GHSA as primary with the CVE as its alias. Grouping
// on the primary identifier alone would split one vulnerability into two
// findings and report agreement as disagreement.
//
// The identifiers form a graph: every finding contributes edges between all the
// identifiers it names. Each connected component is one real vulnerability.
// This is union-find over those components.
type aliasGraph struct {
	parent map[string]string
}

func newAliasGraph() *aliasGraph {
	return &aliasGraph{parent: map[string]string{}}
}

// add records that every identifier in the reference names the same
// vulnerability.
func (g *aliasGraph) add(ref model.VulnRef) {
	ids := ref.AllIDs()
	if len(ids) == 0 {
		return
	}
	first := ids[0].ID
	g.find(first)
	for _, id := range ids[1:] {
		g.union(first, id.ID)
	}
}

// find returns the representative of the set containing id, creating a new
// single-element set if it has not been seen. It compresses paths as it goes,
// which keeps repeated lookups cheap on the thousands of identifiers a scan
// produces.
func (g *aliasGraph) find(id string) string {
	root, seen := g.parent[id]
	if !seen {
		g.parent[id] = id
		return id
	}
	for root != g.parent[root] {
		g.parent[root] = g.parent[g.parent[root]] // halve the path
		root = g.parent[root]
	}
	g.parent[id] = root
	return root
}

// union merges the sets containing a and b.
func (g *aliasGraph) union(a, b string) {
	ra, rb := g.find(a), g.find(b)
	if ra == rb {
		return
	}
	// Attach deterministically so that the same input always produces the same
	// grouping. Without this, map iteration order would make correlation
	// non-reproducible between runs.
	if ra < rb {
		g.parent[rb] = ra
	} else {
		g.parent[ra] = rb
	}
}

// canonicalIDs returns, for each identifier, the identifier chosen to represent
// its group.
//
// A CVE is preferred where the group contains one, because it is the scheme
// most external sources key on — EPSS and the CISA KEV catalogue both do.
// Otherwise the lexicographically smallest identifier is used, which is
// arbitrary but stable.
func (g *aliasGraph) canonicalIDs(refs []model.VulnRef) map[string]model.VulnID {
	groups := map[string][]model.VulnID{}
	for _, ref := range refs {
		for _, id := range ref.AllIDs() {
			root := g.find(id.ID)
			if !containsID(groups[root], id) {
				groups[root] = append(groups[root], id)
			}
		}
	}

	out := map[string]model.VulnID{}
	for root, ids := range groups {
		canonical := pickCanonical(ids)
		for _, id := range ids {
			out[id.ID] = canonical
		}
		out[root] = canonical
	}
	return out
}

// pickCanonical chooses the identifier that represents a group.
func pickCanonical(ids []model.VulnID) model.VulnID {
	best := ids[0]
	for _, id := range ids[1:] {
		switch {
		case id.IsCVE() && !best.IsCVE():
			best = id
		case id.IsCVE() == best.IsCVE() && id.ID < best.ID:
			best = id
		}
	}
	return best
}

// mergeAliases returns every identifier in a group, with the canonical one as
// primary and the rest as aliases, ordered for stable output.
func mergeAliases(ids []model.VulnID) model.VulnRef {
	canonical := pickCanonical(ids)
	ref := model.VulnRef{Primary: canonical}
	for _, id := range ids {
		if !id.Equal(canonical) {
			ref.Aliases = append(ref.Aliases, id)
		}
	}
	sortIDs(ref.Aliases)
	return ref
}

func containsID(ids []model.VulnID, want model.VulnID) bool {
	for _, id := range ids {
		if id.Equal(want) {
			return true
		}
	}
	return false
}

// sortIDs orders identifiers by their string form. Insertion sort: alias lists
// are a handful of entries at most.
func sortIDs(ids []model.VulnID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j].ID < ids[j-1].ID; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}
