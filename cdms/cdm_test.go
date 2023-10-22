package cdms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL3CDM(t *testing.T) {
	assert.Greater(t, len(L3), 0)
	t.Logf("L3 CDM: %v", len(L3))
}
