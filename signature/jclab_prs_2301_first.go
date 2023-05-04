package signature

import (
	"crypto"
)

func init() {
	addEngine(NewJclabPrs2301FirstEngine())
}

func NewJclabPrs2301FirstEngine() Engine {
	return &jclabPrs2301FirstEngine{}
}

type jclabPrs2301FirstEngine struct {
	Engine
}

type jclabPrs2301FirstSigner struct {
	Signer
	key   *JclabPrs2301PrivateKey
	keyId string
}

type jclabPrs2301FirstVerifier struct {
	Verifier
	key   *JclabPrs2301PublicKey
	keyId string
}

func (e *jclabPrs2301FirstEngine) Schema() string {
	return "jclab-prs-2301:first"
}

func (e *jclabPrs2301FirstEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2301PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2301FirstEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	keyImpl, ok := key.(*JclabPrs2301PrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2301FirstEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	keyImpl, ok := privateKey.(*JclabPrs2301PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return NewJclabPrs2301PublicKey(keyImpl.curve, keyImpl.keyType, keyImpl.w1)
}

func (e *jclabPrs2301FirstEngine) NewSigner(key crypto.PrivateKey, keyId string) (Signer, error) {
	keyImpl, ok := key.(*JclabPrs2301PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2301FirstSigner{
		key:   keyImpl,
		keyId: keyId,
	}, nil
}

func (e *jclabPrs2301FirstEngine) NewVerifier(key crypto.PublicKey, keyId string) (Verifier, error) {
	keyImpl, ok := key.(*JclabPrs2301PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2301FirstVerifier{
		key:   keyImpl,
		keyId: keyId,
	}, nil
}

func (e *jclabPrs2301FirstSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *jclabPrs2301FirstSigner) PublicKey() crypto.PublicKey {
	return jclabPrs2301PrivateToPublic(e.key)
}

func (e *jclabPrs2301FirstSigner) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2301FirstSigner) SignMessage(msg []byte) ([]byte, error) {
	sig, err := e.key.curve.Sign(msg, e.key.s)
	if err != nil {
		return nil, err
	}
	return sig.Encode(), nil
}

func (e *jclabPrs2301FirstSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func (e *jclabPrs2301FirstVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *jclabPrs2301FirstVerifier) KeyId() string {
	return e.keyId
}

func (e *jclabPrs2301FirstVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	sig1 := e.key.curve.Signature1FromBytes(sig)
	return e.key.curve.FirstVerify(sig1, msg, e.key.w1), nil
}

func (e *jclabPrs2301FirstVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}
