package keys

//import (
//	"crypto/ed25519"
//	"crypto/rand"
//	"encoding/hex"
//	"encoding/json"
//	"errors"
//	"github.com/stretchr/testify/assert"
//	"io"
//	"strings"
//	"testing"
//
//	fuzz "github.com/google/gofuzz"
//	"github.com/theupdateframework/go-tuf/data"
//)
//
//var testingEd25519Engine = NewEd25519Engine()
//
//func TestUnmarshalEd25519(t *testing.T) {
//	pub, _, err := ed25519.GenerateKey(strings.NewReader("00001-deterministic-buffer-for-key-generation"))
//	assert.Nil(t, err)
//
//	publicKey, err := json.Marshal(map[string]string{
//		"public": hex.EncodeToString(pub),
//	})
//	assert.Nil(t, err)
//
//	badKey := &data.PublicKey{
//		Type:       data.KeyTypeEd25519,
//		Scheme:     data.KeySchemeEd25519,
//		Algorithms: data.HashAlgorithms,
//		Value:      publicKey,
//	}
//	verifier, err := testingEd25519Engine.NewVerifier(badKey)
//
//	c.Assert(verifier.UnmarshalPublicKey(badKey), IsNil)
//}
//
//func TestUnmarshalEd25519_Invalid(t *testing.T) {
//	badKeyValue, err := json.Marshal(true)
//	assert.Nil(t, err)
//	badKey := &data.PublicKey{
//		Type:       data.KeyTypeEd25519,
//		Scheme:     data.KeySchemeEd25519,
//		Algorithms: data.HashAlgorithms,
//		Value:      badKeyValue,
//	}
//	verifier := NewEd25519Verifier()
//	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
//}
//
//func TestUnmarshalEd25519_FastFuzz(t *testing.T) {
//	verifier := NewEd25519Verifier()
//	for i := 0; i < 50; i++ {
//		// Ensure no basic panic
//
//		f := fuzz.New()
//		var publicData data.PublicKey
//		f.Fuzz(&publicData)
//
//		verifier.UnmarshalPublicKey(&publicData)
//	}
//}
//
//func TestUnmarshalEd25519_TooLongContent(t *testing.T) {
//	randomSeed := make([]byte, MaxJSONKeySize)
//	_, err := io.ReadFull(rand.Reader, randomSeed)
//	assert.Nil(t, err)
//
//	tooLongPayload, err := json.Marshal(
//		&ed25519Verifier{
//			PublicKey: data.HexBytes(hex.EncodeToString(randomSeed)),
//		},
//	)
//	assert.Nil(t, err)
//
//	badKey := &data.PublicKey{
//		Type:       data.KeyTypeEd25519,
//		Scheme:     data.KeySchemeEd25519,
//		Algorithms: data.HashAlgorithms,
//		Value:      tooLongPayload,
//	}
//	verifier := NewEd25519Verifier()
//	err = verifier.UnmarshalPublicKey(badKey)
//	c.Assert(errors.Is(err, io.ErrUnexpectedEOF), Equals, true)
//}
//
//func TestSignVerify(t *testing.T) {
//	signer, err := GenerateEd25519Key()
//	assert.Nil(t, err)
//	msg := []byte("foo")
//	sig, err := signer.SignMessage(msg)
//	assert.Nil(t, err)
//	publicData := signer.PublicData()
//	pubKey, err := GetVerifier(publicData)
//	assert.Nil(t, err)
//	c.Assert(pubKey.Verify(msg, sig), IsNil)
//}
