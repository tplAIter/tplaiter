//go:build linux

package gen

// Linux dev_t is already uint64; keep every device bit, including high bits.
func nativeDeviceID(dev uint64) uint64 { return dev }
