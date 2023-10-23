package device

import (
	"bytes"
	_ "embed"
	wvpb "github.com/iyear/gowidevine/widevinepb"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL3Device(t *testing.T) {
	assert.Greater(t, len(L3), 0)
	t.Logf("L3 Devices: %v", len(L3))
}

//go:embed l3/4464/client_id
var clientID []byte

//go:embed l3/4464/private_key
var privateKey []byte

func TestNewDevice(t *testing.T) {
	device, err := New(clientID, privateKey)
	require.NoError(t, err)

	assert.Equal(t, uint32(4464), device.DrmCertificate().GetSystemId())
	assert.Equal(t, wvpb.ClientIdentification_DRM_DEVICE_CERTIFICATE, device.ClientID().GetType())
	assert.Equal(t, 1434, len(device.ClientID().GetToken()))
	assert.Equal(t, 8, len(device.ClientID().GetClientInfo()))
	assert.Equal(t, 256, device.PrivateKey().Size())
}

//go:embed testdata/samsung.wvd
var wvd []byte

func TestFromWVD(t *testing.T) {
	device, err := FromWVD(bytes.NewReader(wvd))
	require.NoError(t, err)

	assert.Equal(t, uint32(5536), device.DrmCertificate().GetSystemId())
	assert.Equal(t, wvpb.ClientIdentification_DRM_DEVICE_CERTIFICATE, device.ClientID().GetType())
	assert.Equal(t, 1434, len(device.ClientID().GetToken()))
	assert.Equal(t, 8, len(device.ClientID().GetClientInfo()))
	assert.Equal(t, 256, device.PrivateKey().Size())
}
