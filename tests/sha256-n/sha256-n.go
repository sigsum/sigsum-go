package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func main() {
	log.SetFlags(0)
	n := 1
	if len(os.Args) > 1 {
		var err error
		n, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatalf("invalid number: %v", err)
		}
		if n < 1 {
			log.Fatalf("count must be positive, but got %d", n)
		}
	}
	h, err := crypto.HashFile(os.Stdin)
	if err != nil {
		log.Fatalf("failed reading input: %v", err)
	}
	for n--; n > 0; n-- {
		h = crypto.HashBytes(h[:])
	}
	fmt.Printf("%x\n", h)
}
