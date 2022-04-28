package options

import (
	"flag"
	"fmt"
)

const (
	DefaultString = "default string"
	DefaultUint64 = 18446744073709551615
)

// New initializes a flag set using the provided arguments.
//
//   - args should start with the (sub)command's name
//   - usage is a function that prints a usage message
//   - set is a function that sets the command's flag arguments
//
func New(args []string, usage func(), set func(*flag.FlagSet)) *flag.FlagSet {
	if len(args) == 0 {
		args = append(args, "")
	}

	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	fs.Usage = func() {
		usage()
	}
	set(fs)
	fs.Parse(args[1:])
	return fs
}

// AddString adds a string option to a flag set
func AddString(fs *flag.FlagSet, opt *string, short, long, value string) {
	fs.StringVar(opt, short, value, "")
	fs.StringVar(opt, long, value, "")
}

// AddUint64 adds an uint64 option to a flag set
func AddUint64(fs *flag.FlagSet, opt *uint64, short, long string, value uint64) {
	fs.Uint64Var(opt, short, value, "")
	fs.Uint64Var(opt, long, value, "")
}

// CheckString checks that a string option has a non-default value
func CheckString(optionName, value string, err error) error {
	if err != nil {
		return err
	}
	if value == DefaultString {
		return fmt.Errorf("%s is a required option", optionName)
	}
	return nil
}

// CheckUint64 checks that an uint64 option has a non-default value
func CheckUint64(optionName string, value uint64, err error) error {
	if err != nil {
		return err
	}
	if value == DefaultUint64 {
		return fmt.Errorf("%s is a required option", optionName)
	}
	return nil
}
