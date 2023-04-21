package keys

import (
	"crypto"
	"errors"
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

type SignedJson[T any] struct {
	Signed     *T                     `json:"signed"`
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
	MarshalPrivateKey() string

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
