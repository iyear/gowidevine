package widevine

import (
	"crypto/rsa"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

//go:embed testdata/license/service-cert
var serviceCert []byte

func TestParseServiceCert(t *testing.T) {
	cert, err := ParseServiceCert(serviceCert)
	require.NoError(t, err)

	assert.Equal(t, wvpb.DrmCertificate_SERVICE, cert.GetType())
	assert.Equal(t, "4f2d27d961597a7cbd8a2a343468eb52", hex.EncodeToString(cert.GetSerialNumber()))
	assert.Equal(t, 270, len(cert.GetPublicKey()))
	assert.Equal(t, "spotify.com", cert.GetProviderId())
}

func TestPtr(t *testing.T) {
	s := "foo"
	assert.EqualValues(t, &s, ptr("foo"))

	i := 42
	assert.EqualValues(t, &i, ptr(42))
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		input     []byte
		blockSize int
		expected  []byte
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, 8, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, 8, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}},
		{[]byte("OpenAI"), 16, []byte("OpenAI\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a")},
		{[]byte("12345"), 2, []byte("12345\x01")},
		{[]byte(""), 10, []byte("\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a")},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, pkcs7Padding(test.input, test.blockSize))
	}
}

func TestPKCS7Unpadding(t *testing.T) {
	tests := []struct {
		input     []byte
		blockSize int
		expected  []byte
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8, []byte{0x1, 0x2, 0x3, 0x10}},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}},
		{[]byte("OpenAI\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a"), 16, []byte("OpenAI")},
		{[]byte("12345\x01"), 2, []byte("12345")},
		{[]byte("\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a"), 10, []byte("")},
	}

	for _, test := range tests {
		b, err := pkcs7Unpadding(test.input, test.blockSize)
		require.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestParsePublicKey(t *testing.T) {
	originalPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes([]byte{0x00, 0x01, 0x23, 0x45}),
		E: 65537,
	}

	encodedPublicKey, err := asn1.Marshal(*originalPublicKey)
	require.NoError(t, err)

	parsedPublicKey, err := parsePublicKey(encodedPublicKey)
	require.NoError(t, err)

	assert.Equal(t, originalPublicKey, parsedPublicKey)
}
