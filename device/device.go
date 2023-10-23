package device

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"path"

	"google.golang.org/protobuf/proto"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

const (
	clientIDFile   = "client_id"
	privateKeyFile = "private_key"
)

type Device struct {
	clientID   *wvpb.ClientIdentification
	cert       *wvpb.DrmCertificate
	privateKey *rsa.PrivateKey
}

func New(clientID, privateKey []byte) (*Device, error) {
	return toDevice(clientID, privateKey)
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

//go:embed l1
var l1 embed.FS

// L1 is a collection of built-in L1 devices.
var L1 []*Device

//go:embed l3
var l3 embed.FS

// L3 is a collection of built-in L3 devices.
var L3 []*Device

func init() {
	if err := readBuildIns(); err != nil {
		panic(err)
	}
}

func readBuildIns() error {
	cdms := map[string]struct {
		fs      embed.FS
		devices *[]*Device
	}{
		"l1": {l1, &L1},
		"l3": {l3, &L3},
		// TODO: add l1 and l2
	}

	for name, cdm := range cdms {
		dir, err := cdm.fs.ReadDir(name)
		if err != nil {
			return fmt.Errorf("read dir: %w", err)
		}

		for _, file := range dir {
			if !file.IsDir() {
				return fmt.Errorf("%s dir should not contain a regular file", name)
			}

			base := path.Join(name, file.Name())

			clientIDData, err := cdm.fs.ReadFile(path.Join(base, clientIDFile))
			if err != nil {
				return fmt.Errorf("read client id: %w", err)
			}

			privateKeyData, err := cdm.fs.ReadFile(path.Join(base, privateKeyFile))
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}

			device, err := toDevice(clientIDData, privateKeyData)
			if err != nil {
				return fmt.Errorf("to device: %w", err)
			}

			*cdm.devices = append(*cdm.devices, device)
		}
	}

	return nil
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

func FromWVD(r io.Reader) (*Device, error) {
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
