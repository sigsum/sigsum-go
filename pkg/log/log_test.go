package log

import (
	"os"
)

func Example() {
	SetOutput(os.Stdout)
	SetLevel(WarningLevel)
	SetDate(false)
	SetColor(false)

	Debug("some debug number: %d\n", 10)
	Info("some info number: %d\n", 20)
	Warning("some warning number: %d\n", 30)
	Error("some error number: %d\n", 40)

	// Output:
	// [WARN] some warning number: 30
	// [ERRO] some error number: 40
}
