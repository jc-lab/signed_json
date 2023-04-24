package keys

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
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
	//Signer
	key ed25519.PrivateKey
}

type ed25519Verifier struct {
	//Verifier
	key ed25519.PublicKey
}

func (e ed25519Engine) Schema() string {
	return "ed25519"
}

func (e ed25519Engine) GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	return private, public, err
}

func (e ed25519Engine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	edkey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return edkey.Public(), nil
}

func (e ed25519Engine) MarshalPublicKey(key crypto.PublicKey) (string, error) {
	edkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return base64.RawURLEncoding.EncodeToString(edkey), nil
}

func (e ed25519Engine) UnmarshalPublicKey(key string) (crypto.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func (e ed25519Engine) MarshalPrivateKey(key crypto.PrivateKey) (string, error) {
	edkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return ed25519MarshalPrivateKey(edkey), nil
}

func (e ed25519Engine) UnmarshalPrivateKey(key string) (crypto.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(bytes.NewReader(raw))
	return privateKey, err
}

func (e ed25519Engine) MarshalPublicKeyRaw(key crypto.PublicKey) ([]byte, error) {
	edkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	clone := make([]byte, len(edkey))
	copy(clone, edkey)
	return clone, nil
}

func (e ed25519Engine) UnmarshalPublicKeyRaw(key []byte) (crypto.PublicKey, error) {
	return ed25519.PublicKey(key), nil
}

func (e ed25519Engine) MarshalPrivateKeyRaw(key crypto.PrivateKey) ([]byte, error) {
	edkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	clone := make([]byte, len(edkey))
	copy(clone, edkey)
	return clone, nil
}

func (e ed25519Engine) UnmarshalPrivateKeyRaw(key []byte) (crypto.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(bytes.NewReader(key))
	return privateKey, err
}

func (e ed25519Engine) NewSigner(key crypto.PrivateKey) (Signer, error) {
	edkey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519Signer{
		key: edkey,
	}, nil
}

func (e ed25519Engine) NewVerifier(key crypto.PublicKey) (Verifier, error) {
	edkey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519Verifier{
		key: edkey,
	}, nil
}

func (e *ed25519Signer) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *ed25519Signer) PublicKey() crypto.PublicKey {
	return ed25519PrivateToPublic(e.key)
}

func (e *ed25519Signer) KeyId() string {
	public := ed25519PrivateToPublic(e.key)
	return ed25519KeyId(public)
}

func (e *ed25519Signer) MarshalPrivateKey() string {
	return ed25519MarshalPrivateKey(e.key)
}

func (e *ed25519Signer) SignMessage(msg []byte) ([]byte, error) {
	return e.key.Sign(rand.Reader, msg, crypto.Hash(0))
}

func (e *ed25519Signer) SignJson(msg *SignedJson[any]) error {
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

func (e *ed25519Verifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *ed25519Verifier) KeyId() string {
	return ed25519KeyId(e.key)
}

func (e *ed25519Verifier) MarshalPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.key)
}

func (e *ed25519Verifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	return ed25519.Verify(e.key, msg, sig), nil
}

func (e *ed25519Verifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	encoded, err := cjson.EncodeCanonical(msg.Signed)
	if err != nil {
		return false, err
	}
	keyid := ed25519KeyId(e.key)
	for _, signature := range msg.Signatures {
		sigRaw, err := base64.RawURLEncoding.DecodeString(signature.Sig)
		if err != nil {
			return false, err
		}

		if signature.Keyid == keyid {
			return e.VerifyMessage(encoded, sigRaw)
		}
	}

	return false, ErrInvalidKey
}

func ed25519MarshalPrivateKey(key ed25519.PrivateKey) string {
	raw := []byte(key)
	return base64.RawURLEncoding.EncodeToString(raw[:32])
}

func ed25519PrivateToPublic(key ed25519.PrivateKey) ed25519.PublicKey {
	publicKey, _, _ := ed25519.GenerateKey(bytes.NewReader(key))
	return publicKey
}

func ed25519KeyId(key ed25519.PublicKey) string {
	md := crypto.SHA256.New()
	md.Write(key)
	return base64.RawURLEncoding.EncodeToString(md.Sum(nil))
}
