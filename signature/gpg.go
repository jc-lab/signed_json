package signature

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"github.com/ProtonMail/go-crypto/openpgp"
	"io"
	"os"
	"os/exec"
	"runtime"
)

var (
	ErrGpgNotSupported = errors.New("GPG Not Supported")
	ErrGpgCancelled    = errors.New("cancelled")
)

type GpgConfig struct {
	Command    string // default: gpg(.exe)
	UseAgent   bool
	Passphrase string
	KeyName    string
}

type gpgPrivateKey struct {
	crypto.PrivateKey
	Command    string
	UseAgent   bool
	Passphrase string
	KeyName    string
}

type gpgPublicKey struct {
	crypto.PublicKey
	armor      string
	entityList openpgp.EntityList
}

type gpgSigner struct {
	Signer
	key       *gpgPrivateKey
	publicKey *gpgPublicKey
}

func NewGpgSigner(config *GpgConfig) (Signer, error) {
	signer := &gpgSigner{
		key: &gpgPrivateKey{
			Command:  "gpg",
			UseAgent: true,
		},
	}
	if config != nil {
		signer.key.Command = config.Command
		signer.key.KeyName = config.KeyName
		signer.key.UseAgent = config.UseAgent
		signer.key.Passphrase = config.Passphrase
	}

	publicArmor, err := gpgExport(signer.key.Command, signer.key.KeyName)
	if err != nil {
		return nil, err
	}

	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicArmor))
	if err != nil {
		return nil, err
	}

	signer.publicKey = &gpgPublicKey{
		armor:      string(publicArmor),
		entityList: entityList,
	}

	return signer, nil
}

func (e *gpgSigner) PrivateKey() crypto.PrivateKey {
	return e.key
}

func (e *gpgSigner) PublicKey() crypto.PublicKey {
	return e.publicKey
}

func (e *gpgSigner) KeyId() string {
	return base64.RawURLEncoding.EncodeToString(e.publicKey.entityList[0].PrimaryKey.Fingerprint)
}

func (e *gpgSigner) SignMessage(msg []byte) ([]byte, error) {
	return gpgSign(e.key.Command, e.key.UseAgent, e.key.KeyName, e.key.Passphrase, msg)
}

func (e *gpgSigner) SignJson(msg *SignedJson[any]) error {
	return signJson(e, msg)
}

func gpgSign(command string, useAgent bool, keyname string, passphrase string, msg []byte) ([]byte, error) {
	var args = []string{
		"--sign",
		"--detach-sign",
	}

	if command == "" {
		command = "gpg"
		if runtime.GOOS == "windows" {
			command += ".exe"
		}
	}

	if useAgent {
		args = append(args, "--use-agent")
	} else {
		args = append(args, "--no-use-agent")
	}
	if passphrase != "" {
		args = append(args, "--pinentry-mode", "loopback", "--batch", "--passphrase-fd", "0")
	}
	if keyname != "" {
		args = append(args, "--local-user", keyname)
	}

	inputFile, err := os.CreateTemp("", "sjd*.tmp")
	if err != nil {
		return nil, err
	}
	sigFileName := inputFile.Name() + ".sig"

	inputFile.Write(msg)
	inputFile.Close()

	defer func() {
		inputFile.Close()
		os.Remove(inputFile.Name())
		os.Remove(sigFileName)
	}()

	args = append(args, inputFile.Name())

	cmd := exec.Command(command, args...)

	if passphrase != "" {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		defer stdin.Close()
		n, err := io.WriteString(stdin, passphrase+"\n")
		if err != nil {
			return nil, err
		}
		println("WRITTEN", n)
	}

	stdout, err := cmd.StdoutPipe()
	if err == nil {
		go io.Copy(os.Stderr, stdout)
	}
	stderr, err := cmd.StderrPipe()
	if err == nil {
		go io.Copy(os.Stderr, stderr)
	}

	if err := cmd.Run(); err != nil {
		if cmd.ProcessState.ExitCode() == 2 {
			return nil, ErrGpgCancelled
		}
		return nil, err
	}

	sig, err := os.ReadFile(inputFile.Name() + ".sig")
	return sig, err
}

func gpgExport(command string, keyname string) ([]byte, error) {
	var args = []string{
		"--armor",
		"--export",
		keyname,
	}

	if command == "" {
		command = "gpg"
		if runtime.GOOS == "windows" {
			command += ".exe"
		}
	}

	cmd := exec.Command(command, args...)

	stderr, err := cmd.StderrPipe()
	if err == nil {
		go io.Copy(os.Stderr, stderr)
	}

	return cmd.Output()
}
