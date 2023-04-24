package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var testingEd25519Engine = NewEd25519Engine()

func Test_ed25519Engine_Schema(t *testing.T) {
	assert.Equal(t, testingEd25519Engine.Schema(), "ed25519")
}

func Test_ed25519Engine_GenerateKeyPair(t *testing.T) {
	privateKey, publicKey, err := testingEd25519Engine.GenerateKeyPair()
	assert.Nil(t, err)

	regenPublicKey, err := testingEd25519Engine.GeneratePublicKey(privateKey)
	assert.Nil(t, err)

	assert.Equal(t, publicKey, regenPublicKey)
}

func Test_ed25519Engine_GeneratePublicKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader("00001-deterministic-buffer-for-key-generation"))

	regenPublicKey, err := testingEd25519Engine.GeneratePublicKey(privateKey)
	assert.Nil(t, err)

	assert.Equal(t, publicKey, regenPublicKey)

	regenPublicKeyRaw, _ := testingEd25519Engine.MarshalPublicKeyRaw(regenPublicKey)
	assert.Equal(t, "424176ad7cb070035ecf4abb624f94fd8b257dc83b7df3a4bab91b77b77a567d", hex.EncodeToString(regenPublicKeyRaw))
}

func Test_ed25519Engine_TestSignVerify(t *testing.T) {
	privateKeyRaw, _ := hex.DecodeString("30303030312d64657465726d696e69737469632d6275666665722d666f722d6b")
	privateKey, err := testingEd25519Engine.UnmarshalPrivateKeyRaw(privateKeyRaw)
	assert.Nil(t, err)

	signer, err := testingEd25519Engine.NewSigner(privateKey)
	assert.Nil(t, err)

	verifier, err := testingEd25519Engine.NewVerifier(signer.PublicKey())
	assert.Nil(t, err)

	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	assert.Nil(t, err)

	res, err := verifier.VerifyMessage(msg, sig)
	assert.Nil(t, err)
	assert.True(t, res)

	msg[0] ^= 0x01
	res, err = verifier.VerifyMessage(msg, sig)
	assert.Nil(t, err)
	assert.False(t, res)
}
