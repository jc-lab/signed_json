package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

const ecdsaKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEftgasQA68yvumeXZmcOTSIHKfbmx
WT1oYuRF0Un3tKxnzip6xAYwlz0Dt96DUh+0P7BruHH2O6s4MiRR9/TuNw==
-----END PUBLIC KEY-----
`

func Test_pkix_MarshalJSON(t *testing.T) {
	block, _ := pem.Decode([]byte(ecdsaKey))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.Nil(t, err)
	k := PKIXPublicKey{PublicKey: key}
	buf, err := json.Marshal(&k)
	assert.Nil(t, err)
	var val string
	err = json.Unmarshal(buf, &val)
	assert.Nil(t, err)
	assert.Equal(t, ecdsaKey, val)
}

func Test_pkix_UnmarshalJSON(t *testing.T) {
	buf, err := json.Marshal(ecdsaKey)
	assert.Nil(t, err)
	var k PKIXPublicKey
	err = json.Unmarshal(buf, &k)
	assert.Nil(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, k.PublicKey)
}

func Test_pkix_UnmarshalPKIX_TooLongContent(t *testing.T) {
	randomSeed := make([]byte, MaxJSONKeySize)
	_, err := io.ReadFull(rand.Reader, randomSeed)
	assert.Nil(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: randomSeed,
	})
	tooLongPayload, err := json.Marshal(string(pemBytes))
	assert.Nil(t, err)

	var k PKIXPublicKey
	err = json.Unmarshal(tooLongPayload, &k)
	assert.EqualError(t, err, "the public key is truncated or too large: unexpected EOF")
}
