package signature

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testingEd25519Engine           = NewEd25519Engine()
	testingEd25519PrivateKeyRaw, _ = hex.DecodeString("30303030312d64657465726d696e69737469632d6275666665722d666f722d6b")
	testingEd25519PrivateKey, _    = NewEd25519PrivateKeyFromRaw(testingEd25519PrivateKeyRaw)
)

func Test_ed25519_GetEngine(t *testing.T) {
	engine, err := GetEngine("ed25519")
	assert.Nil(t, err)
	assert.IsType(t, &ed25519Engine{}, engine)
}

func Test_ed25519Engine_Schema(t *testing.T) {
	assert.Equal(t, testingEd25519Engine.Schema(), "ed25519")
}

func Test_ed25519Engine_GeneratePublicKey(t *testing.T) {
	publicKey, err := testingEd25519Engine.GeneratePublicKey(testingEd25519PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, "424176ad7cb070035ecf4abb624f94fd8b257dc83b7df3a4bab91b77b77a567d", hex.EncodeToString(publicKey.(ed25519.PublicKey)))
}

func Test_ed25519Engine_KeyTypeByPublicKey(t *testing.T) {
	publicKey, _ := testingEd25519Engine.GeneratePublicKey(testingEd25519PrivateKey)
	keyType, _ := testingEd25519Engine.KeyTypeByPublicKey(publicKey)
	assert.Equal(t, "ed25519", keyType)
}

func Test_ed25519Engine_KeyTypeByPrivateKey(t *testing.T) {
	keyType, _ := testingEd25519Engine.KeyTypeByPrivateKey(testingEd25519PrivateKey)
	assert.Equal(t, "ed25519", keyType)
}

func Test_ed25519Engine_SignVerifyJson(t *testing.T) {
	privateKeyRaw, _ := hex.DecodeString("30303030312d64657465726d696e69737469632d6275666665722d666f722d6b")

	privateKey, _ := NewEd25519PrivateKeyFromRaw(privateKeyRaw)

	signer, err := testingEd25519Engine.NewSigner(privateKey, "aaaa")
	assert.Nil(t, err)

	publicKey, err := testingEd25519Engine.GeneratePublicKey(privateKey)
	assert.Nil(t, err)

	verifier, err := testingEd25519Engine.NewVerifier(publicKey, "aaaa")
	assert.Nil(t, err)

	commonJsonTest(t, signer, verifier, "aaaa", "KEL5U1lLRkknEoGgQQpOuDEqgZT20AggzVhzIuRVxiAeVJPT798vObTXLRdse6oRbHrFMg4rfSSFFLJjUHCRDw")
}
