//go:build !android

package cmd

import (
	"golang.org/x/term"
	"os"
)

func readSecretBytes() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	// piped input (e.g. in scripts)
	var buf []byte
	tmp := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(tmp)
		if n > 0 && tmp[0] != '\n' && tmp[0] != '\r' {
			buf = append(buf, tmp[0])
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}
