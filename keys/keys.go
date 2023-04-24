package keys

import (
	"crypto"
	"encoding/base64"
	"errors"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"sync"
)

var (
	ErrInvalid    = errors.New("tuf: signature verification failed")
	ErrInvalidKey = errors.New("invalid key")
)

const (
	MaxJSONKeySize = 512 * 1024
)

type SignedJsonSignature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

type SignedJson[T interface{}] struct {
	Signed     T                      `json:"signed"`
	Signatures []*SignedJsonSignature `json:"signatures"`
}

type Engine interface {
	Schema() string
	GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error)
	GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error)
	MarshalPublicKey(key crypto.PublicKey) (string, error)
	UnmarshalPublicKey(key string) (crypto.PublicKey, error)
	MarshalPrivateKey(key crypto.PrivateKey) (string, error)
	UnmarshalPrivateKey(key string) (crypto.PrivateKey, error)
	MarshalPublicKeyRaw(key crypto.PublicKey) ([]byte, error)
	UnmarshalPublicKeyRaw(key []byte) (crypto.PublicKey, error)
	MarshalPrivateKeyRaw(key crypto.PrivateKey) ([]byte, error)
	UnmarshalPrivateKeyRaw(key []byte) (crypto.PrivateKey, error)
	NewSigner(key crypto.PrivateKey) (Signer, error)
	NewVerifier(key crypto.PublicKey) (Verifier, error)
}

type Verifier interface {
	PublicKey() crypto.PublicKey
	KeyId() string
	MarshalPublicKey() string
	VerifyMessage(msg []byte, sig []byte) (bool, error)
	VerifyJson(msg *SignedJson[any]) (bool, error)
}

type Signer interface {
	PrivateKey() crypto.PrivateKey
	PublicKey() crypto.PublicKey
	KeyId() string

	SignMessage(msg []byte) ([]byte, error)
	SignJson(msg *SignedJson[any]) error
}

var engineMap sync.Map

func addEngine(engine Engine) {
	engineMap.Store(engine.Schema(), engine)
}

func GetEngine(schema string) (Engine, error) {
	engine, ok := engineMap.Load(schema)
	if !ok {
		return nil, ErrInvalid
	}
	return engine.(Engine), nil
}

func signJson(e Signer, msg *SignedJson[any]) error {
	encoded, err := cjson.EncodeCanonical(msg.Signed)
	if err != nil {
		return err
	}
	signature, err := e.SignMessage(encoded)
	if err != nil {
		return err
	}
	msg.Signatures = append(msg.Signatures, &SignedJsonSignature{
		Keyid: e.KeyId(),
		Sig:   base64.RawURLEncoding.EncodeToString(signature),
	})
	return nil
}

func verifyJson(e Verifier, msg *SignedJson[any]) (bool, error) {
	encoded, err := cjson.EncodeCanonical(msg.Signed)
	if err != nil {
		return false, err
	}
	for _, signature := range msg.Signatures {
		sigRaw, err := base64.RawURLEncoding.DecodeString(signature.Sig)
		if err != nil {
			return false, err
		}

		if signature.Keyid == e.KeyId() {
			return e.VerifyMessage(encoded, sigRaw)
		}
	}

	return false, ErrInvalidKey
}
