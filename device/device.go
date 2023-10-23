package device

import (
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
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
	SystemID   int
	ClientID   *wvpb.ClientIdentification
	PrivateKey *rsa.PrivateKey
}

//go:embed l3
var l3 embed.FS

// L3 is a collection of built-in L3 devices.
var L3 []Device

func init() {
	if err := readBuildIns(); err != nil {
		panic(err)
	}
}

func readBuildIns() error {
	cdms := map[string]struct {
		fs      embed.FS
		devices *[]Device
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

			sysid, err := strconv.Atoi(file.Name())
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

			*cdm.devices = append(*cdm.devices, Device{
				SystemID:   sysid,
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
