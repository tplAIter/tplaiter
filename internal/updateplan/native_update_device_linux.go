//go:build linux

package updateplan

// Linux dev_t is already uint64. Keep every bit, including the high bits.
func updateDeviceID(dev uint64) uint64 { return dev }
