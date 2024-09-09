package widevine

import (
	"errors"
	"fmt"
	"io"

	wvpb "github.com/iyear/gowidevine/widevinepb"

	"github.com/Eyevinn/mp4ff/mp4"
)

// Adapted from https://github.com/Eyevinn/mp4ff/blob/v0.46.0/cmd/mp4ff-decrypt/main.go

// DecryptMP4 decrypts a fragmented MP4 file with keys from widevice license. Supports CENC and CBCS schemes.
func DecryptMP4(r io.Reader, keys []*Key, w io.Writer) error {
	// Extract content key
	var key []byte
	for _, k := range keys {
		if k.Type == wvpb.License_KeyContainer_CONTENT {
			key = k.Key
			break
		}
	}
	if key == nil {
		return fmt.Errorf("no %s key type found in the provided key set", wvpb.License_KeyContainer_CONTENT)
	}
	// Initialization
	inMp4, err := mp4.DecodeFile(r)
	if err != nil {
		return fmt.Errorf("failed to decode file: %w", err)

	}
	if !inMp4.IsFragmented() {
		return errors.New("file is not fragmented")

	}
	// Handle init segment
	if inMp4.Init == nil {
		return errors.New("no init part of file")

	}
	decryptInfo, err := mp4.DecryptInit(inMp4.Init)
	if err != nil {
		return fmt.Errorf("failed to decrypt init: %w", err)

	}
	if err = inMp4.Init.Encode(w); err != nil {
		return fmt.Errorf("failed to write init: %w", err)

	}
	// Decode segments
	for _, seg := range inMp4.Segments {
		if err = mp4.DecryptSegment(seg, decryptInfo, key); err != nil {
			return fmt.Errorf("failed to decrypt segment: %w", err)

		}
		if err = seg.Encode(w); err != nil {
			return fmt.Errorf("failed to encode segment: %w", err)
		}
	}
	return nil
}
