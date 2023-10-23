package devices

import (
	"embed"
	"fmt"
	widevine "github.com/iyear/gowidevine"
	"path"
)

const (
	clientIDFile   = "client_id"
	privateKeyFile = "private_key"
)

func init() {
	if err := readBuildIns(); err != nil {
		panic(err)
	}
}

//go:embed l1
var l1 embed.FS

// L1 is a collection of built-in L1 devices.
var L1 []*widevine.Device

//go:embed l3
var l3 embed.FS

// L3 is a collection of built-in L3 devices.
var L3 []*widevine.Device

func readBuildIns() error {
	cdms := map[string]struct {
		fs      embed.FS
		devices *[]*widevine.Device
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

			device, err := widevine.NewDevice(clientIDData, privateKeyData)
			if err != nil {
				return fmt.Errorf("to device: %w", err)
			}

			*cdm.devices = append(*cdm.devices, device)
		}
	}

	return nil
}
