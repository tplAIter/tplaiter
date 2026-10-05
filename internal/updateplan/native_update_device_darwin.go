//go:build darwin

package updateplan

// Darwin dev_t is signed int32. Retain its sign-extended identity without
// an unchecked signed-to-unsigned conversion, matching the transaction engine.
func updateDeviceID(dev int32) uint64 {
	if dev >= 0 {
		return uint64(dev)
	}
	complement := ^dev
	if complement < 0 {
		return 0
	}
	return ^uint64(complement)
}
