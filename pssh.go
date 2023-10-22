package gowidevine

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/Eyevinn/mp4ff/mp4"
	"google.golang.org/protobuf/proto"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

const WidevineSystemID = "edef8ba979d64acea3c827dcd51d21ed"

type PSSH struct {
	box  *mp4.PsshBox
	data *wvpb.WidevinePsshData
}

func NewPSSH(b []byte) (*PSSH, error) {
	box, err := mp4.DecodeBox(0, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("decode box: %w", err)
	}

	psshBox, ok := box.(*mp4.PsshBox)
	if !ok {
		return nil, fmt.Errorf("box is a %s instead of a PSSH", box.Type())
	}

	if hex.EncodeToString(psshBox.SystemID) != WidevineSystemID {
		return nil, fmt.Errorf("system id is %s instead of widevine", hex.EncodeToString(psshBox.SystemID))
	}

	data := &wvpb.WidevinePsshData{}
	if err = proto.Unmarshal(psshBox.Data, data); err != nil {
		return nil, fmt.Errorf("unmarshal pssh data: %w", err)
	}

	return &PSSH{
		box:  psshBox,
		data: data,
	}, nil
}

func (p *PSSH) Version() byte {
	return p.box.Version
}

func (p *PSSH) Flags() uint32 {
	return p.box.Flags
}

func (p *PSSH) RawData() []byte {
	return p.box.Data
}

func (p *PSSH) Data() *wvpb.WidevinePsshData {
	return p.data
}
