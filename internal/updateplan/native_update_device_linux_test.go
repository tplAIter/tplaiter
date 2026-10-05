//go:build linux

package updateplan

import "testing"

func TestUpdateLinuxDeviceIdentity(t *testing.T) {
	for _, dev := range []uint64{0, 1, 1 << 32, 1 << 63, 0xffffffffffffffff} {
		if got := updateDeviceID(dev); got != dev {
			t.Fatalf("dev_t %x truncated to %x", dev, got)
		}
	}
}
