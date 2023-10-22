package device

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL3Device(t *testing.T) {
	assert.Greater(t, len(L3), 0)
	t.Logf("L3 Devices: %v", len(L3))
}
