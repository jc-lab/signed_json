package keys

import "encoding/base64"

func encode(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

func decode(input string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(input)
}
