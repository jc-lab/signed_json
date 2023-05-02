package keys

import (
	"crypto"
	"errors"
	"github.com/jc-lab/jclab-prs-2301/engine"
)

func init() {
	addEngine(NewJclabPrs2301FinalEngine())
}

func NewJclabPrs2301FinalEngine() Engine {
	return &jclabPrs2301FinalEngine{}
}

type jclabPrs2301FinalEngine struct {
	Engine
}

type jclabPrs2301FinalPrivateKey struct {
	keyType string
	curve   engine.CurveEngine
	key     []byte
}

type jclabPrs2301FinalPublicKey struct {
	keyType string
	curve   engine.CurveEngine
	key     []byte
}

type jclabPrs2301FinalSigner struct {
	Signer
	key *jclabPrs2301ResignKey
}

type jclabPrs2301FinalVerifier struct {
	Verifier
	key *jclabPrs2301PublicKey
}

func (e *jclabPrs2301FinalEngine) Schema() string {
	return "jclab-prs-2301:final"
}

func (e *jclabPrs2301FinalEngine) GenerateKeyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	return nil, nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalEngine) GeneratePublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	keyImpl, ok := privateKey.(*jclabPrs2301ResignKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return NewJclabPrs2301PublicKey(keyImpl.curve, keyImpl.keyType, keyImpl.w1)
}

func (e *jclabPrs2301FinalEngine) MarshalPublicKey(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*jclabPrs2301PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.MarshalPublicKey(), nil
}

func (e *jclabPrs2301FinalEngine) UnmarshalPublicKey(key string) (crypto.PublicKey, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalEngine) MarshalPrivateKey(key crypto.PrivateKey) (string, error) {
	keyImpl, ok := key.(*jclabPrs2301PrivateKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return encode(keyImpl.s), nil
}

func (e *jclabPrs2301FinalEngine) UnmarshalPrivateKey(key string) (crypto.PrivateKey, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalEngine) MarshalPublicKeyRaw(key crypto.PublicKey) ([]byte, error) {
	keyImpl, ok := key.(*jclabPrs2301PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return keyImpl.w1, nil
}

func (e *jclabPrs2301FinalEngine) UnmarshalPublicKeyRaw(key []byte) (crypto.PublicKey, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalEngine) MarshalPrivateKeyRaw(key crypto.PrivateKey) ([]byte, error) {
	keyImpl, ok := key.(*jclabPrs2301PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return keyImpl.s, nil
}

func (e *jclabPrs2301FinalEngine) UnmarshalPrivateKeyRaw(key []byte) (crypto.PrivateKey, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalEngine) KeyId(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*jclabPrs2301PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.KeyId(), nil
}

func (e *jclabPrs2301FinalEngine) KeyTypeByPublicKey(key crypto.PublicKey) (string, error) {
	keyImpl, ok := key.(*jclabPrs2301PublicKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2301FinalEngine) KeyTypeByPrivateKey(key crypto.PrivateKey) (string, error) {
	keyImpl, ok := key.(*jclabPrs2301ResignKey)
	if !ok {
		return "", ErrInvalidKey
	}
	return keyImpl.keyType, nil
}

func (e *jclabPrs2301FinalEngine) NewSigner(key crypto.PrivateKey) (Signer, error) {
	keyImpl, ok := key.(*jclabPrs2301ResignKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2301FinalSigner{
		key: keyImpl,
	}, nil
}

func (e *jclabPrs2301FinalEngine) NewVerifier(key crypto.PublicKey) (Verifier, error) {
	keyImpl, ok := key.(*jclabPrs2301PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &jclabPrs2301FinalVerifier{
		key: keyImpl,
	}, nil
}

func (e *jclabPrs2301FinalSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *jclabPrs2301FinalSigner) PublicKey() crypto.PublicKey {
	return jclabPrs2301RkToPublic(e.key)
}

func (e *jclabPrs2301FinalSigner) KeyId() string {
	return e.key.KeyId()
}

func (e *jclabPrs2301FinalSigner) SignMessage(msg []byte) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (e *jclabPrs2301FinalSigner) SignJson(msg *SignedJson[any]) error {
	for _, signature := range msg.Signatures {
		rawSig1, err := decode(signature.Sig)
		if err != nil {
			return err
		}
		sigType := rawSig1[0]
		if sigType != 0x01 {
			return errors.New("invalid signature")
		}
		sig1 := e.key.curve.Signature1FromBytes(rawSig1[1:])
		sig2, err := e.key.curve.PrsResign(sig1, e.key.rk)
		if err != nil {
			return err
		}
		signature.Sig = encode(append([]byte{0x02}, sig2.Encode()...))
		signature.Keyid = e.key.KeyId()
		return nil
	}
	return errors.New("input json is not signed")
}

func (e *jclabPrs2301FinalVerifier) PublicKey() crypto.PublicKey {
	return e.key
}

func (e *jclabPrs2301FinalVerifier) KeyId() string {
	return e.key.KeyId()
}

func (e *jclabPrs2301FinalVerifier) MarshalPublicKey() string {
	return e.key.MarshalPublicKey()
}

func (e *jclabPrs2301FinalVerifier) VerifyMessage(msg []byte, sig []byte) (bool, error) {
	sigType := sig[0]
	if sigType != 0x02 {
		return false, errors.New("invalid signature")
	}
	sig2 := e.key.curve.Signature2FromBytes(sig[1:])
	return e.key.curve.Verify(sig2, msg, e.key.w1), nil
}

func (e *jclabPrs2301FinalVerifier) VerifyJson(msg *SignedJson[any]) (bool, error) {
	return verifyJson(e, msg)
}
