//go:build darwin

package updateplan

import "testing"

func TestUpdateDarwinDeviceIdentity(t *testing.T) {
	for dev, want := range map[int32]uint64{0: 0, 2147483647: 2147483647, -1: 0xffffffffffffffff, -2147483648: 0xffffffff80000000} {
		if got := updateDeviceID(dev); got != want {
			t.Fatalf("dev_t %d: got %x want %x", dev, got, want)
		}
	}
}
