package keys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var testingHmacEngine = NewHmacEngine()

func Test_hmac_GetEngine(t *testing.T) {
	engine, err := GetEngine("hmac")
	assert.Nil(t, err)
	assert.IsType(t, &hmacEngine{}, engine)
}

func Test_hmacEngine_Schema(t *testing.T) {
	assert.Equal(t, testingHmacEngine.Schema(), "hmac")
}

func testHmacSampleKey() *HmacKey {
	return &HmacKey{
		KeyId:     "test",
		SecretKey: []byte("hello"),
		Algorithm: "SHA256",
	}
}

func Test_hmacEngine_SignVerify(t *testing.T) {
	key := testHmacSampleKey()

	signer, err := testingHmacEngine.NewSigner(key)
	assert.Nil(t, err)

	verifier, err := testingHmacEngine.NewVerifier(key)
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

func Test_hmacEngine_keyId(t *testing.T) {
	key := testHmacSampleKey()

	keyId, _ := testingHmacEngine.KeyId(key)
	assert.Equal(t, "test", keyId)
}

func Test_hmacEngine_SignVerifyJson(t *testing.T) {
	key := testHmacSampleKey()

	signer, err := testingHmacEngine.NewSigner(key)
	assert.Nil(t, err)

	verifier, err := testingHmacEngine.NewVerifier(key)
	assert.Nil(t, err)

	root := &SignedJson[any]{
		Signed: &TestMessage{
			Hello: "WORLD",
		},
	}

	err = signer.SignJson(root)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(root.Signatures))

	assert.Equal(t, "test", root.Signatures[0].Keyid)
	assert.Equal(t, "ue270d4MoQpyP9Qer-WBBRTuVsYpDVVCPid7uFIj4Ek", root.Signatures[0].Sig)

	res, err := verifier.VerifyJson(root)
	assert.True(t, res)
}
