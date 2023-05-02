package keys

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testingJclabPrs2301FinalEngine = NewJclabPrs2301FinalEngine()

func Test_jclabPrs2301FinalEngine_GetEngine(t *testing.T) {
	engine, err := GetEngine("jclab-prs-2301:final")
	assert.Nil(t, err)
	assert.IsType(t, &jclabPrs2301FinalEngine{}, engine)
}

func Test_jclabPrs2301FinalEngine_Schema(t *testing.T) {
	assert.Equal(t, testingJclabPrs2301FinalEngine.Schema(), "jclab-prs-2301:final")
}

func Test_jclabPrs2301FinalEngine_keyId(t *testing.T) {
	publicKey, _ := NewJclabPrs2301Bls12381PublicKey(testingJclabPrs2301Bob_W1)

	keyId, _ := testingJclabPrs2301FinalEngine.KeyId(publicKey)
	assert.Equal(t, "PI5IdQih41-q0PVsmqPmv1UI6Afb1fYRPB8rxj-oDEs", keyId)
}

func Test_jclabPrs2301FinalEngine_ReSignVerifyJson(t *testing.T) {
	signedJsonString := "{\"signed\":{\"hello\":\"WORLD\"},\"signatures\":[{\"keyid\":\"Pwb8A6-foIGYtdXq9OhDMe8Ag2NU8BIR9VNEiJknfBc\",\"sig\":\"AQIZ8vH8s6pnMN4g-UstWzfJLxSF0_FScLocvEwuPFitvsZlZiuDgKEqcGfkJQhtZbkORTPwH6j_nLidh79HFG95uLZaxS7PcOs3uZiuvPSaO_5KSHBJAAVtHfB2rJm7jxY-Kw6bFPfo59heorOx3xiKF3HGS5IIe0n8YB9WWJZJ8g\"}]}"

	resignKey, _ := NewJclabPrs2301Bls12381ResignKey(testingJclabPrs2301AliceToBob_RK, testingJclabPrs2301Bob_W1)

	signer, err := testingJclabPrs2301FinalEngine.NewSigner(resignKey)
	assert.Nil(t, err)

	publicKey, _ := NewJclabPrs2301Bls12381PublicKey(testingJclabPrs2301Bob_W1)
	verifier, err := testingJclabPrs2301FinalEngine.NewVerifier(publicKey)
	assert.Nil(t, err)

	root := &SignedJson[any]{
		Signed: &TestMessage{},
	}
	err = json.Unmarshal([]byte(signedJsonString), root)
	assert.Nil(t, err)

	err = signer.SignJson(root)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(root.Signatures))

	assert.Equal(t, "PI5IdQih41-q0PVsmqPmv1UI6Afb1fYRPB8rxj-oDEs", root.Signatures[0].Keyid)

	res, err := verifier.VerifyJson(root)
	assert.True(t, res)
}
