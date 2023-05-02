package keys

import (
	"encoding/base64"
	"github.com/jc-lab/jclab-prs-2301/engine"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testingJclabPrs2301FirstEngine = NewJclabPrs2301FirstEngine()

var (
	testingJclabPrs2301Bls12381, _ = engine.NewBLS12381Engine()

	testingJclabPrs2301Alice_S, _  = base64.RawURLEncoding.DecodeString("FsafwnA2xEibPErXM0G0_dr3tBtZS9C45P9s-Ry6N-I")
	testingJclabPrs2301Alice_W1, _ = base64.RawURLEncoding.DecodeString("AgxeoRZJOUkrgJLgjSnNKbRLZxxeqTktcR_RG4jRkgAXIPF8g9BdbqvrWFsWm7X4bw")
	testingJclabPrs2301Alice_W2, _ = base64.RawURLEncoding.DecodeString("AgcFybh8HCVvh14aJqz8mf8pulmHOwU23sSnih0ZgwKo_M1pEFBpdvGid5J5X7fi3xCmCgDtAbcRUktST4LzahQw-4seBG-3mQE3oO9_4TGkexQsjjfWlz3P1G4K6T7tEw")

	testingJclabPrs2301Bob_S, _  = base64.RawURLEncoding.DecodeString("T4OKowkb3OARsvTzqQYSKO_tPJQAdSbRQaCHDhHwhJ8")
	testingJclabPrs2301Bob_W1, _ = base64.RawURLEncoding.DecodeString("Axmc2yYH04804aRsGR0bnbK3Zoz99itzagN2MI7VcpFuqdYZ2JY6DRsbBrXybMBTwQ")
	testingJclabPrs2301Bob_W2, _ = base64.RawURLEncoding.DecodeString("AgX38iPqAD0epVokMbKhcjVtavWyy6B2QMn8x9rkG9JuskuZKiAurYOqB2RnVKmSIRlgjTESS9VVPiZwcbTAkMkw2Op8HGwd9GO8hUStSm940Wz0V7OX7FSNrTvQ2LrVHQ")

	testingJclabPrs2301AliceToBob_RK, _ = base64.RawURLEncoding.DecodeString("AhdMl3tsR-otVSllyZe3-ioGh8eBeZwz9DggOM3r9QwcNCxMr3e8x-OUXVT_MRV7vRI50HyyfHWGjU1Hi_fcNyGLdWKJY_wXt5E3xt19wid3h__hDLfL3WtDWYIBjyCQkA")
)

func Test_jclabPrs2301FirstEngine_GetEngine(t *testing.T) {
	engine, err := GetEngine("jclab-prs-2301:first")
	assert.Nil(t, err)
	assert.IsType(t, &jclabPrs2301FirstEngine{}, engine)
}

func Test_jclabPrs2301FirstEngine_Schema(t *testing.T) {
	assert.Equal(t, testingJclabPrs2301FirstEngine.Schema(), "jclab-prs-2301:first")
}

func Test_jclabPrs2301FirstEngine_SignVerify(t *testing.T) {
	privateKey, _ := NewJclabPrs2301Bls12381PrivateKey(testingJclabPrs2301Alice_S)

	privateKeyImpl, _ := privateKey.(*jclabPrs2301PrivateKey)
	assert.Equal(t, testingJclabPrs2301Alice_W1, privateKeyImpl.w1)

	signer, err := testingJclabPrs2301FirstEngine.NewSigner(privateKey)
	assert.Nil(t, err)

	verifier, err := testingJclabPrs2301FirstEngine.NewVerifier(signer.PublicKey())
	assert.Nil(t, err)

	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	assert.Nil(t, err)

	res, err := verifier.VerifyMessage(msg, sig)
	assert.Nil(t, err)
	assert.True(t, res)

	msg[0] ^= 0x01
	res, err = verifier.VerifyMessage(msg, sig)
	assert.False(t, res)
}

func Test_jclabPrs2301FirstEngine_keyId(t *testing.T) {
	publicKey, _ := NewJclabPrs2301Bls12381PublicKey(testingJclabPrs2301Alice_W1)

	keyId, _ := testingJclabPrs2301FirstEngine.KeyId(publicKey)
	assert.Equal(t, "Pwb8A6-foIGYtdXq9OhDMe8Ag2NU8BIR9VNEiJknfBc", keyId)
}

func Test_jclabPrs2301FirstEngine_SignVerifyJson(t *testing.T) {
	privateKey, _ := NewJclabPrs2301Bls12381PrivateKey(testingJclabPrs2301Alice_S)

	signer, err := testingJclabPrs2301FirstEngine.NewSigner(privateKey)
	assert.Nil(t, err)

	verifier, err := testingJclabPrs2301FirstEngine.NewVerifier(signer.PublicKey())
	assert.Nil(t, err)

	root := &SignedJson[any]{
		Signed: &TestMessage{
			Hello: "WORLD",
		},
	}

	err = signer.SignJson(root)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(root.Signatures))

	assert.Equal(t, "Pwb8A6-foIGYtdXq9OhDMe8Ag2NU8BIR9VNEiJknfBc", root.Signatures[0].Keyid)

	res, err := verifier.VerifyJson(root)
	assert.True(t, res)
}
