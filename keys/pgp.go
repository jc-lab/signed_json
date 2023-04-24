package keys

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func init() {
	addEngine(NewPgpEngine())
}

func NewPgpEngine() Engine {
	return &pgpEngine{}
}

type pgpEngine struct {
	Engine
}

type pgpPrivateKey struct {
	crypto.PrivateKey
	key *openpgp.Entity
}

type pgpPublicKey struct {
	crypto.PublicKey
	key *openpgp.Entity
}

type pgpSigner struct {
	Signer
	key       *openpgp.Entity
	publicKey *pgpPublicKey
}

type pgpVerifier struct {
	Verifier
	key  *openpgp.Entity
	keys openpgp.EntityList
}

func ReadPgpArmorPrivateKey(input string) (crypto.PrivateKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	key := entityList[0]
	if key.PrivateKey == nil {
		return nil, ErrInvalidKey
	}
	return &pgpPrivateKey{
		key: entityList[0],
	}, nil
}

func ReadPgpArmorPublicKey(input string) (crypto.PublicKey, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(input)))
	if err != nil {
		return nil, err
	}
	return &pgpPublicKey{
		key: entityList[0],
	}, nil
}

func (e pgpEngine) Schema() string {
	return "pgp"
}

func (e pgpEngine) GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	return nil, nil, ErrGpgNotSupported
}

func (e pgpEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	pgpKey, ok := privateKey.(*pgpPrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	entity, err := pgpPrivateToPublic(pgpKey.key)
	if err != nil {
		return nil, err
	}

	return &pgpPublicKey{
		key: entity,
	}, nil
}

func (e pgpEngine) MarshalPublicKey(key crypto.PublicKey) (string, error) {
	pgpKey, ok := key.(*pgpPublicKey)
	if !ok {
		return "", ErrInvalidKey
	}

	var buf bytes.Buffer
	if err := pgpKey.key.Serialize(&buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func (e pgpEngine) UnmarshalPublicKey(key string) (crypto.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	entityList, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &pgpPublicKey{
		key: entityList[0],
	}, nil
}

func (e pgpEngine) MarshalPrivateKey(key crypto.PrivateKey) (string, error) {
	pgpKey, ok := key.(*pgpPrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}

	var buf bytes.Buffer
	if err := pgpKey.key.SerializePrivate(&buf, &packet.Config{}); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func (e pgpEngine) UnmarshalPrivateKey(key string) (crypto.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	entityList, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &pgpPrivateKey{
		key: entityList[0],
	}, nil
}

func (e pgpEngine) MarshalPublicKeyRaw(key crypto.PublicKey) ([]byte, error) {
	pgpKey, ok := key.(*pgpPublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	var buf bytes.Buffer
	if err := pgpKey.key.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e pgpEngine) UnmarshalPublicKeyRaw(key []byte) (crypto.PublicKey, error) {
	entityList, err := openpgp.ReadKeyRing(bytes.NewReader(key))
	if err != nil {
		return nil, err
	}
	return &pgpPublicKey{
		key: entityList[0],
	}, nil
}

func (e pgpEngine) MarshalPrivateKeyRaw(key crypto.PrivateKey) ([]byte, error) {
	pgpKey, ok := key.(*pgpPrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	var buf bytes.Buffer
	if err := pgpKey.key.SerializePrivate(&buf, &packet.Config{}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e pgpEngine) UnmarshalPrivateKeyRaw(key []byte) (crypto.PrivateKey, error) {
	entityList, err := openpgp.ReadKeyRing(bytes.NewReader(key))
	if err != nil {
		return nil, err
	}
	return &pgpPrivateKey{
		key: entityList[0],
	}, nil
}

func (e pgpEngine) NewSigner(key crypto.PrivateKey) (Signer, error) {
	pgpKey, ok := key.(*pgpPrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	publicKey, err := pgpPrivateToPublic(pgpKey.key)
	if err != nil {
		return nil, err
	}

	return &pgpSigner{
		key: pgpKey.key,
		publicKey: &pgpPublicKey{
			key: publicKey,
		},
	}, nil
}

func (e pgpEngine) NewVerifier(key crypto.PublicKey) (Verifier, error) {
	pgpKey, ok := key.(*pgpPublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &pgpVerifier{
		key:  pgpKey.key,
		keys: []*openpgp.Entity{pgpKey.key},
	}, nil
}

func (e *pgpSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *pgpSigner) PublicKey() crypto.PublicKey {
	return e.publicKey
}

func (e *pgpSigner) KeyId() string {
	return pgpKeyId(e.publicKey.key)
}

func (e *pgpSigner) SignMessage(msg []byte) ([]byte, error) {
	var out bytes.Buffer
	err := openpgp.DetachSign(&out, e.key, bytes.NewReader(msg), &packet.Config{})
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func (e *pgpSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *pgpVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *pgpVerifier) KeyId() string {
	return pgpKeyId(e.key)
}

func (e *pgpVerifier) MarshalPublicKey() string {
	var buf bytes.Buffer
	if err := e.key.Serialize(&buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func (e *pgpVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	_, _, err := openpgp.VerifyDetachedSignature(e.keys, bytes.NewReader(msg), bytes.NewReader(sig), &packet.Config{})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (e *pgpVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}

func pgpKeyId(key *openpgp.Entity) string {
	return base64.RawURLEncoding.EncodeToString(key.PrimaryKey.Fingerprint)
}

func pgpPrivateToPublic(private *openpgp.Entity) (*openpgp.Entity, error) {
	var buf bytes.Buffer
	if err := private.Serialize(&buf); err != nil {
		return nil, err
	}

	keyEntityList, err := openpgp.ReadKeyRing(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, err
	}

	return keyEntityList[0], nil
}
