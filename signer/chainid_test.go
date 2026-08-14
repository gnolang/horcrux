package signer

import "testing"

func TestValidateChainID(t *testing.T) {
	valid := []string{"test", "chain-1", "cosmoshub-4", "osmosis-1", "gaia.testnet", "a_b-c.d"}
	for _, id := range valid {
		if err := ValidateChainID(id); err != nil {
			t.Errorf("ValidateChainID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []string{
		"",
		"../../etc/passwd",
		"../escaped",
		"a/b",
		"a\\b",
		"foo/../bar",
		".",
		"..",
		"has space",
	}
	for _, id := range invalid {
		if err := ValidateChainID(id); err == nil {
			t.Errorf("ValidateChainID(%q) = nil, want error", id)
		}
	}
}
