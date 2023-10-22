package widevine

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

func convertPSSH(t *testing.T, b64 string) []byte {
	b, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	return b
}

func TestNewPSSH(t *testing.T) {
	pssh := convertPSSH(t, "AAAAU3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADMIARIQQATcHlpOAIf1Vdda4clXIBoHc3BvdGlmeSIUQATcHlpOAIf1Vdda4clXIDt20eY=")
	p, err := NewPSSH(pssh)
	require.NoError(t, err)

	assert.Equal(t, byte(0), p.Version())
	assert.Equal(t, uint32(0), p.Flags())
	assert.Equal(t,
		"080112104004dc1e5a4e0087f555d75ae1c957201a0773706f7469667922144004dc1e5a4e0087f555d75ae1c957203b76d1e6",
		hex.EncodeToString(p.RawData()))

	assert.Equal(t, "spotify", p.Data().GetProvider()) // nolint: staticcheck
	assert.Len(t, p.Data().GetKeyIds(), 1)
	assert.Equal(t, "4004dc1e5a4e0087f555d75ae1c95720", hex.EncodeToString(p.Data().GetKeyIds()[0]))
	assert.Equal(t, "4004dc1e5a4e0087f555d75ae1c957203b76d1e6", hex.EncodeToString(p.Data().GetContentId()))
	assert.Equal(t, wvpb.WidevinePsshData_AESCTR, p.Data().GetAlgorithm()) // nolint: staticcheck
}

func TestNewPSSHFail(t *testing.T) {
	tests := []struct {
		name string
		pssh string
	}{
		{name: "invalid box", pssh: "ZmFpbA=="},
		// mp4.CttsBox{EndSampleNr: []uint32{1, 1, 1}, SampleOffset: []int32{1}}
		{name: "invalid box type", pssh: "AAAAGGN0dHMAAAAAAAAAAQAAAAAAAAAB"},
		{name: "invalid system id", pssh: "AAAAIHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAAA="},
		// "foo"
		{name: "invalid data", pssh: "AAAAI3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAANmb28="},
	}

	for _, tt := range tests {
		_, err := NewPSSH(convertPSSH(t, tt.pssh))
		assert.Error(t, err)
	}
}
