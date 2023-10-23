package widevine

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

type Device struct {
	clientID   *wvpb.ClientIdentification
	cert       *wvpb.DrmCertificate
	privateKey *rsa.PrivateKey
}

type DeviceSource func() (*Device, error)

func FromRaw(clientID, privateKey []byte) DeviceSource {
	return func() (*Device, error) {
		return toDevice(clientID, privateKey)
	}
}

func FromWVD(r io.Reader) DeviceSource {
	return func() (*Device, error) {
		return fromWVD(r)
	}
}

func NewDevice(src DeviceSource) (*Device, error) {
	return src()
}

func (d *Device) ClientID() *wvpb.ClientIdentification {
	return d.clientID
}

func (d *Device) DrmCertificate() *wvpb.DrmCertificate {
	return d.cert
}

func (d *Device) PrivateKey() *rsa.PrivateKey {
	return d.privateKey
}

type wvdHeader struct {
	Signature     [3]byte
	Version       uint8
	Type          uint8
	SecurityLevel uint8
	Flags         byte
}

type wvdDataV2 struct {
	PrivateKeyLen uint16
	PrivateKey    []byte
	ClientIDLen   uint16
	ClientID      []byte
}

func fromWVD(r io.Reader) (*Device, error) {
	header := &wvdHeader{}
	if err := binary.Read(r, binary.BigEndian, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if header.Signature != [3]byte{'W', 'V', 'D'} {
		return nil, fmt.Errorf("invalid signature: %v", header.Signature)
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read rest bytes: %w", err)
	}

	switch header.Version {
	case 2:
		data := &wvdDataV2{}
		data.PrivateKeyLen = binary.BigEndian.Uint16(rest[:2])
		data.PrivateKey = rest[2 : 2+data.PrivateKeyLen]
		data.ClientIDLen = binary.BigEndian.Uint16(rest[2+data.PrivateKeyLen : 2+data.PrivateKeyLen+2])
		data.ClientID = rest[2+data.PrivateKeyLen+2 : 2+data.PrivateKeyLen+2+data.ClientIDLen]

		return toDevice(data.ClientID, data.PrivateKey)
	default:
		return nil, fmt.Errorf("unsupported version: %d", header.Version)
	}
}

func toDevice(clientID, privateKey []byte) (*Device, error) {
	c := &wvpb.ClientIdentification{}
	if err := proto.Unmarshal(clientID, c); err != nil {
		return nil, fmt.Errorf("unmarshal client id: %w", err)
	}

	signedCert := &wvpb.SignedDrmCertificate{}
	if err := proto.Unmarshal(c.Token, signedCert); err != nil {
		return nil, fmt.Errorf("unmarshal signed cert: %w", err)
	}

	cert := &wvpb.DrmCertificate{}
	if err := proto.Unmarshal(signedCert.DrmCertificate, cert); err != nil {
		return nil, fmt.Errorf("unmarshal cert: %w", err)
	}

	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &Device{
		clientID:   c,
		cert:       cert,
		privateKey: key,
	}, nil
}

// parsePrivateKey modified from https://go.dev/src/crypto/tls/tls.go#L339
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	var b = make([]byte, len(data))
	copy(b, data)

	if bytes.HasPrefix(data, []byte("-----")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing private key")
		}
		b = block.Bytes
	}

	if key, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", k)
		}
	}

	return nil, fmt.Errorf("unsupported private key type")
}
