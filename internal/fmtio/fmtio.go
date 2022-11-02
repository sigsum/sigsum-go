// package fmtio provides basic utilities to format input and output
package fmtio

import (
	"bytes"
	"io/ioutil"
	"os"
)

// StringFromStdin reads bytes from stdin, parsing them as a string without
// leading and trailing white space
func StringFromStdin() (string, error) {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
}
