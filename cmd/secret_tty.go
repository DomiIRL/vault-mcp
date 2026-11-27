//go:build !android

package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"

	"golang.org/x/term"
)

func readSecretBytes() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	// piped input (e.g. in scripts)
	buf, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	buf = bytes.TrimRight(buf, "\r\n")
	if bytes.ContainsAny(buf, "\r\n") {
		return nil, errors.New("value spans several lines, store it with add --file")
	}
	return buf, nil
}
