package devices

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestL3Device(t *testing.T) {
	assert.Greater(t, len(L1), 0)
	t.Logf("L1 Devices: %v", len(L1))

	assert.Greater(t, len(L3), 0)
	t.Logf("L3 Devices: %v", len(L3))
}
