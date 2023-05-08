package signature

import "encoding/base64"

func Encode(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

func Decode(input string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(input)
}
