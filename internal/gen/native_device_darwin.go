//go:build darwin

package gen

// Darwin dev_t is signed int32. Preserve the existing sign-extended identity
// for negative values without an unchecked signed-to-unsigned conversion.
func nativeDeviceID(dev int32) uint64 {
	if dev >= 0 {
		return uint64(dev)
	}
	complement := ^dev
	// The complement of a negative int32 is nonnegative. Keep the range check
	// explicit at the conversion boundary, including for static range analysis.
	if complement < 0 {
		return 0
	}
	return ^uint64(complement)
}
