package signature

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"errors"
	"hash"
	"strings"
)

func init() {
	addEngine(NewHmacEngine())
}

func NewHmacEngine() Engine {
	return &hmacEngine{}
}

type hmacEngine struct {
	Engine
}

type hmacSigner struct {
	Signer
	key   *HmacKey
	keyId string
}

type hmacVerifier struct {
	Verifier
	key   *HmacKey
	keyId string
}

type HmacKey struct {
	Algorithm string
	SecretKey []byte
}

func (e *hmacEngine) Schema() string {
	return "hmac"
}

func (e *hmacEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return hmacKey.Algorithm, nil
}

func (e *hmacEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return hmacKey.Algorithm, nil
}

func (e *hmacEngine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &hmacSigner{
		key:   hmacKey,
		keyId: keyId,
	}, nil
}

func (e *hmacEngine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &hmacVerifier{
		key:   hmacKey,
		keyId: keyId,
	}, nil
}

func (e *hmacSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *hmacSigner) PublicKey() crypto.PublicKey {
	return nil
}

func (e *hmacSigner) KeyId() string {
	return e.keyId
}

func (e *hmacSigner) SignMessage(msg []byte) ([]byte, error) {
	return hmacCompute(e.key, msg)
}

func (e *hmacSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *hmacVerifier) PublicKey() crypto.PublicKey {
	return nil
}

func (e *hmacVerifier) KeyId() string {
	return e.keyId
}

func (e *hmacVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	computed, err := hmacCompute(e.key, msg)
	if err != nil {
		return false, err
	}
	return bytes.Equal(computed, sig), nil
}

func (e *hmacVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}

func getHashAlgorithm(name string) (func() hash.Hash, error) {
	name = strings.Replace(name, "-", "", -1)
	name = strings.ToLower(name)
	switch name {
	case "sha256":
		return crypto.SHA256.New, nil
	case "sha384":
		return crypto.SHA384.New, nil
	case "sha512":
		return crypto.SHA512.New, nil
	}
	return nil, errors.New("unknown algorithm: " + name)
}

func hmacCompute(key *HmacKey, msg []byte) ([]byte, error) {
	hashFunc, err := getHashAlgorithm(key.Algorithm)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hashFunc, key.SecretKey)
	mac.Write(msg)
	return mac.Sum(nil), nil
}
