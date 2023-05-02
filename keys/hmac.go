package keys

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
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
	key *HmacKey
}

type hmacVerifier struct {
	Verifier
	key *HmacKey
}

type HmacKey struct {
	Algorithm string
	KeyId     string
	SecretKey []byte
}

func (e *hmacEngine) Schema() string {
	return "hmac"
}

func (e *hmacEngine) GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	buffer := make([]byte, 32)
	rand.Read(buffer)
	return &HmacKey{
		Algorithm: "sha256",
		KeyId:     "",
		SecretKey: buffer,
	}, nil, nil
}

func (e *hmacEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) MarshalPublicKey(key crypto.PublicKey) (string, error) {
	return "", errors.New("not support")
}

func (e *hmacEngine) UnmarshalPublicKey(key string) (crypto.PublicKey, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) MarshalPrivateKey(key crypto.PrivateKey) (string, error) {
	return "", errors.New("not support")
}

func (e *hmacEngine) UnmarshalPrivateKey(key string) (crypto.PrivateKey, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) MarshalPublicKeyRaw(key crypto.PublicKey) ([]byte, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) UnmarshalPublicKeyRaw(key []byte) (crypto.PublicKey, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) MarshalPrivateKeyRaw(key crypto.PrivateKey) ([]byte, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) UnmarshalPrivateKeyRaw(key []byte) (crypto.PrivateKey, error) {
	return nil, errors.New("not support")
}

func (e *hmacEngine) KeyId(key crypto.PublicKey) (string, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return hmacKeyId(hmacKey), nil
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

func (e *hmacEngine) NewSigner(key crypto.PrivateKey) (Signer, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &hmacSigner{
		key: hmacKey,
	}, nil
}

func (e *hmacEngine) NewVerifier(key crypto.PublicKey) (Verifier, error) {
	hmacKey, ok := key.(*HmacKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &hmacVerifier{
		key: hmacKey,
	}, nil
}

func (e *hmacSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *hmacSigner) PublicKey() crypto.PublicKey {
	return nil
}

func (e *hmacSigner) KeyId() string {
	return hmacKeyId(e.key)
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
	return hmacKeyId(e.key)
}

func (e *hmacVerifier) MarshalPublicKey() string {
	return ""
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

func hmacMarshalPrivateKey(key *HmacKey) string {
	return base64.RawURLEncoding.EncodeToString(key.SecretKey[:32])
}

func hmacKeyId(key *HmacKey) string {
	return key.KeyId
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
