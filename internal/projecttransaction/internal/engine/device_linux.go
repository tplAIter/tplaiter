//go:build linux

package engine

// Linux dev_t is already uint64; keep every device bit, including high bits.
func deviceID(dev uint64) uint64 { return dev }
