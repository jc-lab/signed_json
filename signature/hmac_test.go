package signature

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

func Test_hmacEngine_KeyTypeByPublicKey(t *testing.T) {
	keyType, _ := testingHmacEngine.KeyTypeByPublicKey(testHmacSampleKey())
	assert.Equal(t, "SHA256", keyType)
}

func Test_hmacEngine_KeyTypeByPrivateKey(t *testing.T) {
	keyType, _ := testingHmacEngine.KeyTypeByPrivateKey(testHmacSampleKey())
	assert.Equal(t, "SHA256", keyType)
}

func Test_hmacEngine_SignVerifyJson(t *testing.T) {
	key := testHmacSampleKey()

	signer, err := testingHmacEngine.NewSigner(key, "aaaa")
	assert.Nil(t, err)

	verifier, err := testingHmacEngine.NewVerifier(key, "aaaa")
	assert.Nil(t, err)

	commonJsonTest(t, signer, verifier, "aaaa", "ue270d4MoQpyP9Qer-WBBRTuVsYpDVVCPid7uFIj4Ek")
}

func testHmacSampleKey() *HmacKey {
	return &HmacKey{
		SecretKey: []byte("hello"),
		Algorithm: "SHA256",
	}
}
