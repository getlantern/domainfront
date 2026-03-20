package domainfront

import (
	"crypto/sha256"
)

// GenerateSNI deterministically selects an SNI from the config's arbitrary
// SNI list based on a hash of the IP address. Returns empty string if
// arbitrary SNIs are not configured.
func GenerateSNI(config *SNIConfig, ipAddress string) string {
	if config == nil || !config.UseArbitrarySNIs || len(config.ArbitrarySNIs) == 0 {
		return ""
	}
	hash := sha256.Sum256([]byte(ipAddress))
	idx := int(hash[0]) % len(config.ArbitrarySNIs)
	return config.ArbitrarySNIs[idx]
}
