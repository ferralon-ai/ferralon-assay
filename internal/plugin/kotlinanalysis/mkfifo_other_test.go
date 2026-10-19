//go:build !unix

package kotlinanalysis

import "errors"

func mkfifo(string) error { return errors.New("no FIFOs on this platform") }
