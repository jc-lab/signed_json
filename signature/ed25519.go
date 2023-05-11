package signature

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

func init() {
	addEngine(NewEd25519Engine())
}

func NewEd25519Engine() Engine {
	return &ed25519Engine{}
}

type ed25519Engine struct {
	Engine
}

type ed25519Signer struct {
	Signer
	engine Engine
	key    ed25519.PrivateKey
	keyId  string
}

type ed25519Verifier struct {
	Verifier
	engine Engine
	key    ed25519.PublicKey
	keyId  string
}

func NewEd25519PrivateKeyFromRaw(key []byte) (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(bytes.NewReader(key))
	return privateKey, err
}

func (e *ed25519Engine) Schema() string {
	return "ed25519"
}

func (e *ed25519Engine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	edkey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return edkey.Public(), nil
}

func (e *ed25519Engine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	_, ok := key.(ed25519.PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return "ed25519", nil
}

func (e *ed25519Engine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	_, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return "ed25519", nil
}

func (e *ed25519Engine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	edkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519Signer{
		engine: e,
		key:    edkey,
		keyId:  keyId,
	}, nil
}

func (e *ed25519Engine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	edkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519Verifier{
		engine: e,
		key:    edkey,
		keyId:  keyId,
	}, nil
}

func (e *ed25519Signer) Engine() Engine {
	return e.engine
}

func (e *ed25519Signer) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *ed25519Signer) PublicKey() crypto.PublicKey {
	return ed25519PrivateToPublic(e.key)
}

func (e *ed25519Signer) KeyId() string {
	return e.keyId
}

func (e *ed25519Signer) SignMessage(msg []byte) ([]byte, error) {
	return e.key.Sign(rand.Reader, msg, crypto.Hash(0))
}

func (e *ed25519Signer) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *ed25519Verifier) Engine() Engine {
	return e.engine
}

func (e *ed25519Verifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *ed25519Verifier) KeyId() string {
	return e.keyId
}

func (e *ed25519Verifier) MarshalPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.key)
}

func (e *ed25519Verifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	return ed25519.Verify(e.key, msg, sig), nil
}

func (e *ed25519Verifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}
func ed25519PrivateToPublic(key ed25519.PrivateKey) ed25519.PublicKey {
	publicKey, _, _ := ed25519.GenerateKey(bytes.NewReader(key))
	return publicKey
}
