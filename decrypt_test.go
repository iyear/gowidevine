package widevine

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeHex(t require.TestingT, h string) []byte {
	b, err := hex.DecodeString(h)
	require.NoError(t, err)
	return b
}

func TestDecryptMP4(t *testing.T) {
	readFile := func(path string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "mp4", path))
		require.NoError(t, err)
		return b
	}

	tests := []struct {
		name     string
		input    string
		key      string
		expected string
	}{
		{name: "cenc", input: "cenc_enc.mp4", key: "63cb5f7184dd4b689a5c5ff11ee6a328", expected: "cenc_dec.mp4"},
		{name: "cbcs", input: "cbcs_enc.mp4", key: "22bdb0063805260307ee5045c0f3835a", expected: "cbcs_dec.mp4"},
		{name: "cbcs_audio", input: "cbcs_audio_enc.mp4", key: "5ffd93861fa776e96cccd934898fc1c8", expected: "cbcs_audio_dec.mp4"},
		{name: "audio", input: "audio_enc.mp4", key: "20be4041a33c7a081e43b2b4378d6d5c", expected: "audio_dec.mp4"},
	}

	for _, tt := range tests {
		buf := bytes.NewBuffer(nil)

		err := DecryptMP4(bytes.NewReader(readFile(tt.input)), decodeHex(t, tt.key), buf)
		require.NoError(t, err, tt.name)

		assert.Equal(t, readFile(tt.expected), buf.Bytes(), tt.name)
	}
}
