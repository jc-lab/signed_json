package keys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ed25519_GetEngine(t *testing.T) {
	engine, err := GetEngine("ed25519")
	assert.Nil(t, err)
	assert.IsType(t, &ed25519Engine{}, engine)
}
