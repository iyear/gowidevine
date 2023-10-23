package device

import (
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"path"
	"strconv"

	"google.golang.org/protobuf/proto"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

const (
	clientIDFile   = "client_id"
	privateKeyFile = "private_key"
)

type Device struct {
	SystemID   uint32
	ClientID   *wvpb.ClientIdentification
	PrivateKey *rsa.PrivateKey
}

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

			sysid, err := strconv.ParseUint(file.Name(), 10, 32)
			if err != nil {
				return fmt.Errorf("system id conv: %w", err)
			}

			base := path.Join(name, file.Name())

			clientIDData, err := cdm.fs.ReadFile(path.Join(base, clientIDFile))
			if err != nil {
				return fmt.Errorf("read client id: %w", err)
			}
			clientID := &wvpb.ClientIdentification{}
			if err := proto.Unmarshal(clientIDData, clientID); err != nil {
				return fmt.Errorf("unmarshal client id: %w", err)
			}

			privateKeyData, err := cdm.fs.ReadFile(path.Join(base, privateKeyFile))
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}
			block, _ := pem.Decode(privateKeyData)
			// TODO: other types of private key
			privateKey, err := parsePrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse private key: %w", err)
			}

			*cdm.devices = append(*cdm.devices, &Device{
				SystemID:   uint32(sysid),
				ClientID:   clientID,
				PrivateKey: privateKey,
			})
		}
	}

	return nil
}

// parsePrivateKey modified from https://go.dev/src/crypto/tls/tls.go#L339
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", k)
		}
	}

	return nil, fmt.Errorf("unsupported private key type")
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
		SystemID:   cert.GetSystemId(),
		ClientID:   c,
		PrivateKey: key,
	}, nil
}
