package widevine

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

//go:embed testdata/device/client_id
var clientID []byte

//go:embed testdata/device/private_key
var privateKey []byte

func TestFromRaw(t *testing.T) {
	device, err := NewDevice(FromRaw(clientID, privateKey))
	require.NoError(t, err)

	assert.Equal(t, uint32(4464), device.DrmCertificate().GetSystemId())
	assert.Equal(t, wvpb.ClientIdentification_DRM_DEVICE_CERTIFICATE, device.ClientID().GetType())
	assert.Equal(t, 1434, len(device.ClientID().GetToken()))
	assert.Equal(t, 8, len(device.ClientID().GetClientInfo()))
	assert.Equal(t, 256, device.PrivateKey().Size())
}

//go:embed testdata/device/test.wvd
var wvd []byte

func TestFromWVD(t *testing.T) {
	device, err := NewDevice(FromWVD(bytes.NewReader(wvd)))
	require.NoError(t, err)

	assert.Equal(t, uint32(5536), device.DrmCertificate().GetSystemId())
	assert.Equal(t, wvpb.ClientIdentification_DRM_DEVICE_CERTIFICATE, device.ClientID().GetType())
	assert.Equal(t, 1434, len(device.ClientID().GetToken()))
	assert.Equal(t, 8, len(device.ClientID().GetClientInfo()))
	assert.Equal(t, 256, device.PrivateKey().Size())
}
