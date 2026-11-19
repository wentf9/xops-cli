package config

// NodeProvenance explicitly classifies how a connection target or snapshot was
// materialized so routing, option precedence, persistence, and credentials never
// rely on nodeID string-prefix heuristics.
type NodeProvenance uint8

const (
	// ProvenanceUnknown indicates an unspecified origin (zero value).
	ProvenanceUnknown NodeProvenance = iota
	// ProvenanceSavedManaged indicates a node loaded from saved XOps inventory.
	ProvenanceSavedManaged
	// ProvenanceOpenSSHVirtual indicates a read-only OpenSSH virtual node resolved
	// directly from OpenSSH config under the "openssh:" namespace.
	ProvenanceOpenSSHVirtual
	// ProvenanceOpenSSHDerived indicates an unpersisted session connection derived
	// from an OpenSSH Host alias (including both canonicalized user@addr:port IDs
	// and collision-disambiguated openssh:user@alias:port IDs).
	ProvenanceOpenSSHDerived
	// ProvenanceAdHocPending indicates an unpersisted ad-hoc session connection
	// that did not originate from an OpenSSH Host alias.
	ProvenanceAdHocPending
)

// String returns a stable human-readable name for debugging and logging.
func (p NodeProvenance) String() string {
	switch p {
	case ProvenanceSavedManaged:
		return "saved_managed"
	case ProvenanceOpenSSHVirtual:
		return "openssh_virtual"
	case ProvenanceOpenSSHDerived:
		return "openssh_derived"
	case ProvenanceAdHocPending:
		return "adhoc_pending"
	default:
		return "unknown"
	}
}

// IsSaved reports whether the connection originates from persisted XOps inventory.
func (p NodeProvenance) IsSaved() bool {
	return p == ProvenanceSavedManaged
}

// IsOpenSSH reports whether the connection originates from OpenSSH configuration.
func (p NodeProvenance) IsOpenSSH() bool {
	return p == ProvenanceOpenSSHVirtual || p == ProvenanceOpenSSHDerived
}

// IsUnpersistedOpenSSH reports whether Tier-4 OpenSSH options should apply
// directly without persisted Tier-2 node overrides.
func (p NodeProvenance) IsUnpersistedOpenSSH() bool {
	return p == ProvenanceOpenSSHVirtual || p == ProvenanceOpenSSHDerived
}
