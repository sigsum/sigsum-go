package log

import (
	"log"
	"os"
)

func Example() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0) // To disable date and time output.
	err := SetLevelFromString("warning")
	if err != nil {
		panic(err)
	}

	Debug("some debug number: %d\n", 10)
	Info("some info number: %d\n", 20)
	Warning("some warning number: %d\n", 30)
	Error("some error number: %d\n", 40)

	// Output:
	// [WARN] some warning number: 30
	// [ERRO] some error number: 40
}
