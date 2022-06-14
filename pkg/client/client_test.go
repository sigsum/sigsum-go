package client

//import (
//	"context"
//	"time"
//
//	"git.sigsum.org/sigsum-go/internal/fmtio"
//	"git.sigsum.org/sigsum-go/pkg/log"
//	"git.sigsum.org/sigsum-go/pkg/requests"
//)
//
//const (
//	//logURL       = "https://poc.sigsum.org/crocodile-icefish/sigsum/v0"
//	logURL       = "http://localhost:4711/crocodile-icefish/sigsum/v0"
//	logPublicKey = "4791eff3bfc17f352bcc76d4752b38c07882093a5935a84577c63de224b0f6b3"
//	userAgent    = "example agent"
//)
//
//func Example() {
//	log.SetLevel(log.DebugLevel)
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	logPub, err := fmtio.PublicKeyFromHex(logPublicKey)
//	if err != nil {
//		log.Fatal("%s", err.Error())
//	}
//	cli := New(Config{
//		UserAgent: userAgent,
//		LogURL:    logURL,
//		LogPub:    logPub,
//	})
//
//	cth, err := cli.GetCosignedTreeHead(ctx)
//	if err != nil {
//		log.Fatal("%s", err.Error())
//	}
//
//	log.Debug("tree size is %d", cth.TreeSize)
//
//	leaves, err := cli.GetLeaves(ctx, requests.Leaves{0, cth.TreeSize})
//	if err != nil {
//		log.Fatal("%s", err.Error())
//	}
//
//	for i, leaf := range leaves {
//		log.Debug("leaf %d has key hash %x", i, leaf.KeyHash[:])
//	}
//
//	log.Debug("repeat get-leaves call from index %d to get more leaves", len(leaves))
//
//	// Output:
//}
