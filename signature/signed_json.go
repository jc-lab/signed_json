package signature

import (
	"encoding/base64"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

type SignedJsonSignature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

type SignedJson[T interface{}] struct {
	Signed     T                      `json:"signed"`
	Signatures []*SignedJsonSignature `json:"signatures"`
}

func signJson(e Signer, msg *SignedJson[any]) error {
	encoded, err := cjson.EncodeCanonical(msg.Signed)
	if err != nil {
		return err
	}
	signature, err := e.SignMessage(encoded)
	if err != nil {
		return err
	}
	msg.Signatures = append(msg.Signatures, &SignedJsonSignature{
		Keyid: e.KeyId(),
		Sig:   base64.RawURLEncoding.EncodeToString(signature),
	})
	return nil
}

func verifyJson(e Verifier, msg *SignedJson[any]) (bool, error) {
	encoded, err := cjson.EncodeCanonical(msg.Signed)
	if err != nil {
		return false, err
	}
	for _, signature := range msg.Signatures {
		sigRaw, err := base64.RawURLEncoding.DecodeString(signature.Sig)
		if err != nil {
			return false, err
		}

		if signature.Keyid == e.KeyId() {
			return e.VerifyMessage(encoded, sigRaw)
		}
	}

	return false, ErrInvalidKey
}
