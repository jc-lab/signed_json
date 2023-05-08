package signature

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gowebpki/jcs"
)

type SignedJsonSignature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

type SignedJson[T interface{}] struct {
	Signed     T                      `json:"signed"`
	Signatures []*SignedJsonSignature `json:"signatures"`
}

func cjson(data interface{}) ([]byte, error) {
	first, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(first)
}

func signJson(e Signer, msg *SignedJson[any]) error {
	encoded, err := cjson(msg.Signed)
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
	encoded, err := cjson(msg.Signed)
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
