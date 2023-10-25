package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	widevine "github.com/iyear/gowidevine"
	"github.com/iyear/gowidevine/widevinepb"
)

var (
	clientID   = []byte("foo")
	privateKey = []byte("bar")
	psshData   = []byte("baz")
)

func main() {
	keys, err := getKeys()
	if err != nil {
		panic(err)
	}

	for _, key := range keys {
		fmt.Printf("type: %s, id: %x, key: %x\n", key.Type, key.ID, key.Key)
	}
}

func getKeys() ([]*widevine.Key, error) {
	// Create device
	device, err := widevine.NewDevice(widevine.FromRaw(clientID, privateKey))
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}
	// Create CDM
	cdm := widevine.NewCDM(device)

	// Parse PSSH
	pssh, err := widevine.NewPSSH(psshData)
	if err != nil {
		return nil, fmt.Errorf("parse pssh: %w", err)
	}

	// Get license challenge
	challenge, parseLicense, err := cdm.GetLicenseChallenge(pssh, widevinepb.LicenseType_AUTOMATIC, false)
	if err != nil {
		return nil, fmt.Errorf("get license challenge: %w", err)
	}

	// Send challenge to license server
	resp, err := http.DefaultClient.Do(&http.Request{Body: io.NopCloser(bytes.NewReader(challenge))})
	if err != nil {
		return nil, fmt.Errorf("request license: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	license, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read resp: %w", err)
	}

	// Parse license
	keys, err := parseLicense(license)
	if err != nil {
		return nil, fmt.Errorf("parse license: %w", err)
	}

	return keys, nil
}
