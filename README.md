<h1 align="center">gowidevine</h1>

<p align="center">
🐭 Go implementation of Google's Widevine DRM CDM (Content Decryption Module)
</p>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/iyear/gowidevine?style=flat-square" alt="">
<img src="https://img.shields.io/github/license/iyear/gowidevine?style=flat-square" alt="">
<img src="https://img.shields.io/github/actions/workflow/status/iyear/gowidevine/ci.yml?branch=master&amp;style=flat-square" alt="">
<img src="https://img.shields.io/github/v/release/iyear/gowidevine?color=red&amp;style=flat-square" alt="">
</p>

## Features

- [x] Implementation of Widevine CDM/Device/Protobuf
- [x] Decrypt MP4 with Widevine key
- [x] Covered by realistic data tests
- [x] Few third-party dependencies
- [ ] License proxy server/client

## Getting Started

### Install

You first need [Go](https://go.dev/) installed (version 1.18+ is required), then you can use the below Go command to
install gowidevine:

```shell
go get -u github.com/iyear/gowidevine
```

### Import

Import the package into your project:

```go
import "github.com/iyear/gowidevine"
```

### Usage

```go
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
    if len(keys) == 0 {
        panic("no keys")
    }

    for _, key := range keys {
        fmt.Printf("type: %s, id: %x, key: %x\n", key.Type, key.ID, key.Key)
    }

    err = widevine.DecryptMP4Auto(bytes.NewBufferString("encrypted data"),
        keys, io.Discard)
    if err != nil {
        panic(err)
    }
}

func getKeys() ([]*widevine.Key, error) {
    // Create device from raw data or from wvd file
    device, err := widevine.NewDevice(
        widevine.FromRaw(clientID, privateKey),
        // widevine.FromWVD(bytes.NewReader([]byte("baz"))),
    )
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
    // Or use privacy mode
    cert, err := getServiceCert()
    if err != nil {
        return nil, fmt.Errorf("get service cert: %w", err)
    }
    challenge, parseLicense, err = cdm.GetLicenseChallenge(pssh, widevinepb.LicenseType_AUTOMATIC, true, cert)
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

func getServiceCert() (*widevinepb.DrmCertificate, error) {
    resp, err := http.DefaultClient.Do(&http.Request{Body: io.NopCloser(bytes.NewReader(widevine.ServiceCertificateRequest))})
    if err != nil {
        return nil, fmt.Errorf("request service cert: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()

    serviceCert, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("read response: %w", err)
    }

    cert, err := widevine.ParseServiceCert(serviceCert)
    if err != nil {
        return nil, fmt.Errorf("parse service cert: %w", err)
    }

    return cert, nil
}
```

## Thanks

- [pywidevine](https://github.com/rlaphoenix/pywidevine)
- [mp4ff](https://github.com/Eyevinn/mp4ff/)

## Disclaimer

- The project does not provide Google-provisioned private key and client id except for test purpose.
- The project does not condone piracy or any action against the terms of the DRM systems.
- The project is for study and research only, please do not use it for commercial purposes.

## License

GPLv3 License
