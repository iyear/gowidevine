package widevine

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/protobuf/proto"

	wvpb "github.com/iyear/gowidevine/widevinepb"
)

// ServiceCertificateRequest is the constant request for getting the service certificate from the Widevine license server.
var ServiceCertificateRequest = []byte{0x08, 0x04}

const (
	sessionKeyLength = 16
)

type Key struct {
	// Type is the type of key.
	Type wvpb.License_KeyContainer_KeyType
	// IV is the initialization vector of the key.
	IV []byte
	// ID is the ID of the key.
	ID []byte
	// Key is the key.
	Key []byte
}

// CDM implements the Widevine CDM protocol.
type CDM struct {
	device *Device
	rand   *rand.Rand
	now    func() time.Time
}

type CDMOption func(*CDM)

func defaultCDMOptions() []CDMOption {
	return []CDMOption{
		WithRandom(rand.NewSource(time.Now().UnixNano())),
		WithNow(time.Now),
	}
}

// WithRandom sets the random source of the CDM.
func WithRandom(source rand.Source) CDMOption {
	return func(c *CDM) {
		c.rand = rand.New(source)
	}
}

// WithNow sets the time now source of the CDM.
func WithNow(now func() time.Time) CDMOption {
	return func(c *CDM) {
		c.now = now
	}
}

// NewCDM creates a new CDM.
//
// Get device by calling NewDevice.
func NewCDM(device *Device, opts ...CDMOption) *CDM {
	if device == nil {
		panic("device cannot be nil")
	}

	c := &CDM{
		device: device,
	}

	for _, opt := range defaultCDMOptions() {
		opt(c)
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetLicenseChallenge returns the license challenge for the given PSSH.
//
// Set privacyMode to true to enable privacy mode, and you must provide a service certificate.
func (c *CDM) GetLicenseChallenge(pssh *PSSH, typ wvpb.LicenseType, privacyMode bool, serviceCert ...*wvpb.DrmCertificate) ([]byte, func(b []byte) ([]*Key, error), error) {
	req := &wvpb.LicenseRequest{
		Type:            wvpb.LicenseRequest_NEW.Enum(),
		RequestTime:     ptr(c.now().Unix()),
		ProtocolVersion: wvpb.ProtocolVersion_VERSION_2_1.Enum(),
		KeyControlNonce: ptr(c.rand.Uint32()),
		ContentId: &wvpb.LicenseRequest_ContentIdentification{
			ContentIdVariant: &wvpb.LicenseRequest_ContentIdentification_WidevinePsshData_{
				WidevinePsshData: &wvpb.LicenseRequest_ContentIdentification_WidevinePsshData{
					PsshData:    [][]byte{pssh.RawData()},
					LicenseType: typ.Enum(),
					RequestId: []byte(fmt.Sprintf("%08X%08X0100000000000000",
						c.rand.Uint32(),
						c.rand.Uint32())),
				},
			},
		},
	}

	// set client id
	if privacyMode {
		if len(serviceCert) == 0 {
			return nil, nil, fmt.Errorf("privacy mode must provide cert")
		}

		cert := serviceCert[0]
		encClientID, err := c.encryptClientID(cert)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt client id: %w", err)
		}

		req.EncryptedClientId = encClientID
	} else {
		req.ClientId = c.device.ClientID()
	}

	reqData, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal license request: %w", err)
	}

	// signed license request signature
	hashed := sha1.Sum(reqData)
	pss, err := rsa.SignPSS(
		rand.New(c.rand),
		c.device.PrivateKey(),
		crypto.SHA1,
		hashed[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return nil, nil, fmt.Errorf("sign pss: %w", err)
	}

	msg := &wvpb.SignedMessage{
		Type:      wvpb.SignedMessage_LICENSE_REQUEST.Enum(),
		Msg:       reqData,
		Signature: pss,
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal signed message: %w", err)
	}

	return data, func(license []byte) ([]*Key, error) {
		return c.parseLicense(license, reqData)
	}, nil
}

func (c *CDM) encryptClientID(cert *wvpb.DrmCertificate) (*wvpb.EncryptedClientIdentification, error) {
	privacyKey := c.randomBytes(16)
	privacyIV := c.randomBytes(16)

	block, err := aes.NewCipher(privacyKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	// encryptedClientID
	clientID, err := proto.Marshal(c.device.ClientID())
	if err != nil {
		return nil, fmt.Errorf("marshal client id: %w", err)
	}
	paddedData := pkcs7Padding(clientID, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, privacyIV)
	encryptedClientID := make([]byte, len(paddedData))
	mode.CryptBlocks(encryptedClientID, paddedData)

	// encryptedPrivacyKey
	publicKey, err := parsePublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	encryptedPrivacyKey, err := rsa.EncryptOAEP(
		sha1.New(),
		c.rand,
		publicKey,
		privacyKey,
		nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt oaep: %w", err)
	}

	encClientID := &wvpb.EncryptedClientIdentification{
		ProviderId:                     cert.ProviderId,
		ServiceCertificateSerialNumber: cert.SerialNumber,
		EncryptedClientId:              encryptedClientID,
		EncryptedPrivacyKey:            encryptedPrivacyKey,
		EncryptedClientIdIv:            privacyIV,
	}

	return encClientID, nil
}

func (c *CDM) randomBytes(length int) []byte {
	r := make([]byte, length)
	c.rand.Read(r)
	return r
}

func (c *CDM) parseLicense(license, licenseRequest []byte) ([]*Key, error) {
	signedMsg := &wvpb.SignedMessage{}
	if err := proto.Unmarshal(license, signedMsg); err != nil {
		return nil, fmt.Errorf("unmarshal signed message: %w", err)
	}
	if signedMsg.GetType() != wvpb.SignedMessage_LICENSE {
		return nil, fmt.Errorf("invalid license type: %v", signedMsg.GetType())
	}

	sessionKey, err := c.rsaOAEPDecrypt(c.device.PrivateKey(), signedMsg.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt session key: %w", err)
	}
	if len(sessionKey) != sessionKeyLength {
		return nil, fmt.Errorf("invalid session key length: %v", sessionKey)
	}

	derivedEncKey := deriveEncKey(licenseRequest, sessionKey)
	derivedAuthKey := deriveAuthKey(licenseRequest, sessionKey)

	licenseMsg := &wvpb.License{}
	if err = proto.Unmarshal(signedMsg.Msg, licenseMsg); err != nil {
		return nil, fmt.Errorf("unmarshal license message: %w", err)
	}

	licenseMsgHMAC := hmac.New(sha256.New, derivedAuthKey)
	licenseMsgHMAC.Write(signedMsg.Msg)
	expectedHMAC := licenseMsgHMAC.Sum(nil)
	if !hmac.Equal(signedMsg.Signature, expectedHMAC) {
		return nil, fmt.Errorf("invalid license signature: %v", signedMsg.Signature)
	}

	keys := make([]*Key, 0)
	for _, key := range licenseMsg.Key {
		decryptedKey, err := decryptAES(derivedEncKey, key.Iv, key.Key)
		if err != nil {
			return nil, fmt.Errorf("decrypt aes: %w", err)
		}

		keys = append(keys, &Key{
			Type: key.GetType(),
			IV:   key.Iv,
			ID:   key.GetId(),
			Key:  decryptedKey,
		})
	}

	return keys, nil
}

func (c *CDM) rsaOAEPDecrypt(privateKey *rsa.PrivateKey, encryptedData []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptOAEP(sha1.New(), c.rand, privateKey, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

func deriveEncKey(licenseRequest, sessionKey []byte) []byte {
	encKey := make([]byte, 16+len(licenseRequest))

	copy(encKey[:12], "\x01ENCRYPTION\x00")
	copy(encKey[12:], licenseRequest)
	binary.BigEndian.PutUint32(encKey[12+len(licenseRequest):], 128)

	return cmacAES(encKey, sessionKey)
}

func deriveAuthKey(licenseRequest, sessionKey []byte) []byte {
	authKey := make([]byte, 20+len(licenseRequest))

	copy(authKey[:16], "\x01AUTHENTICATION\x00")
	copy(authKey[16:], licenseRequest)
	binary.BigEndian.PutUint32(authKey[16+len(licenseRequest):], 512)

	authCmacKey1 := cmacAES(authKey, sessionKey)
	authKey[0] = 2
	authCmacKey2 := cmacAES(authKey, sessionKey)

	return append(authCmacKey1, authCmacKey2...)
}
