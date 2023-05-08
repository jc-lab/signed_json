package signature

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

func Test_jclabPrs2301FirstEngine_KeyTypeByPublicKey(t *testing.T) {
	publicKey, _ := NewJclabPrs2301Bls12381PublicKey(testingJclabPrs2301Alice_W1)
	keyType, _ := testingJclabPrs2301FirstEngine.KeyTypeByPublicKey(publicKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2301FirstEngine_KeyTypeByPrivateKey(t *testing.T) {
	privateKey, _ := NewJclabPrs2301Bls12381PrivateKey(testingJclabPrs2301Alice_S)
	keyType, _ := testingJclabPrs2301FirstEngine.KeyTypeByPrivateKey(privateKey)
	assert.Equal(t, "bls12-381", keyType)
}

func Test_jclabPrs2301FirstEngine_SignVerifyJson(t *testing.T) {
	privateKey, _ := NewJclabPrs2301Bls12381PrivateKey(testingJclabPrs2301Alice_S)

	signer, err := testingJclabPrs2301FirstEngine.NewSigner(privateKey, "aaaa")
	assert.Nil(t, err)

	verifier, err := testingJclabPrs2301FirstEngine.NewVerifier(signer.PublicKey(), "aaaa")
	assert.Nil(t, err)

	commonJsonTest(t, signer, verifier, "aaaa", "")
}
