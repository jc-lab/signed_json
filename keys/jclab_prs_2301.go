package keys

import (
	"crypto"
	"github.com/jc-lab/jclab-prs-2301/engine"
)

type jclabPrs2301PrivateKey struct {
	keyType string
	curve   engine.CurveEngine
	s       []byte
	w1      []byte
}

type jclabPrs2301PublicKey struct {
	keyType string
	curve   engine.CurveEngine
	w1      []byte
}

type jclabPrs2301ResignKey struct {
	keyType string
	curve   engine.CurveEngine
	rk      []byte
	w1      []byte
}

func NewJclabPrs2301PrivateKey(curveEngine engine.CurveEngine, keyType string, S []byte) (crypto.PrivateKey, error) {
	w, err := curveEngine.GeneratePublicKey(S)
	if err != nil {
		return nil, err
	}
	return &jclabPrs2301PrivateKey{
		curve:   curveEngine,
		keyType: keyType,
		s:       S,
		w1:      w,
	}, nil
}

func NewJclabPrs2301PublicKey(curveEngine engine.CurveEngine, keyType string, W1 []byte) (crypto.PrivateKey, error) {
	return &jclabPrs2301PublicKey{
		curve:   curveEngine,
		keyType: keyType,
		w1:      W1,
	}, nil
}

func NewJclabPrs2301ResignKey(curveEngine engine.CurveEngine, keyType string, RK []byte, W1 []byte) (crypto.PrivateKey, error) {
	return &jclabPrs2301ResignKey{
		curve:   curveEngine,
		keyType: keyType,
		rk:      RK,
		w1:      W1,
	}, nil
}

func NewJclabPrs2301Bls12381PrivateKey(S []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	w, err := curveEngine.GeneratePublicKey(S)
	if err != nil {
		return nil, err
	}
	return &jclabPrs2301PrivateKey{
		curve:   curveEngine,
		keyType: "bls12-381",
		s:       S,
		w1:      w,
	}, nil
}

func NewJclabPrs2301Bls12381PublicKey(W1 []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	return &jclabPrs2301PublicKey{
		curve:   curveEngine,
		keyType: "bls12-381",
		w1:      W1,
	}, nil
}

func NewJclabPrs2301Bls12381ResignKey(RK []byte, W1 []byte) (crypto.PrivateKey, error) {
	curveEngine, err := engine.NewBLS12381Engine()
	if err != nil {
		return nil, err
	}
	return &jclabPrs2301ResignKey{
		curve:   curveEngine,
		keyType: "bls12-381",
		rk:      RK,
		w1:      W1,
	}, nil
}

func (k *jclabPrs2301PublicKey) KeyId() string {
	md := crypto.SHA256.New()
	md.Write(k.w1)
	return encode(md.Sum(nil))
}

func (k *jclabPrs2301PublicKey) MarshalPublicKey() string {
	return encode(k.w1)
}

func (k *jclabPrs2301ResignKey) KeyId() string {
	md := crypto.SHA256.New()
	md.Write(k.w1)
	return encode(md.Sum(nil))
}

func (k *jclabPrs2301ResignKey) MarshalPublicKey() string {
	return encode(k.w1)
}

func jclabPrs2301PrivateToPublic(key *jclabPrs2301PrivateKey) *jclabPrs2301PublicKey {
	return &jclabPrs2301PublicKey{
		curve:   key.curve,
		keyType: key.keyType,
		w1:      key.w1,
	}
}

func jclabPrs2301RkToPublic(key *jclabPrs2301ResignKey) *jclabPrs2301PublicKey {
	return &jclabPrs2301PublicKey{
		curve:   key.curve,
		keyType: key.keyType,
		w1:      key.w1,
	}
}
