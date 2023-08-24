package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	getopt "github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	keyFile     string
	logKey      string
	stateFile   string
	prefix      string
	hostAndPort string
}

func main() {
	log.SetFlags(0)
	var settings Settings
	settings.parse(os.Args)

	signer, err := key.ReadPrivateKeyFile(settings.keyFile)
	if err != nil {
		log.Fatal(err)
	}
	pub := signer.Public()
	logPub, err := key.ReadPublicKeyFile(settings.logKey)
	if err != nil {
		log.Fatal(err)
	}
	state := state{fileName: settings.stateFile}
	if err := state.Load(&pub, &logPub); err != nil {
		log.Fatal(err)
	}
	witness := witness{
		signer: signer,
		logPub: logPub,
		state:  &state,
	}

	http.HandleFunc("/"+types.EndpointGetTreeSize.Path(settings.prefix), witness.GetTreeSize)
	http.HandleFunc("/"+types.EndpointAddTreeHead.Path(settings.prefix), witness.AddTreeHead)
	server := http.Server{
		Addr: settings.hostAndPort,
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := server.ListenAndServe()
		if err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	shutdownCtx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	server.Shutdown(shutdownCtx)
}

func (s *Settings) parse(args []string) {
	const usage = `
  Provides a service for cosigning a sigsum log (currently, only a
  single log), listening on the given host and port.
`
	set := getopt.New()
	set.SetParameters("host:port")
	set.SetUsage(func() { fmt.Print(usage) })

	help := false

	set.Flag(&s.keyFile, 'k', "Witness private key", "file").Mandatory()
	set.FlagLong(&s.logKey, "log-key", 0, "Log public key", "file").Mandatory()
	// TODO: Better name?
	set.FlagLong(&s.stateFile, "state-file", 0, "Name of state file", "file").Mandatory()
	set.FlagLong(&s.prefix, "url-prefix", 0, "Prefix preceding the endpoint names", "string")
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args, nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
		os.Exit(0)
	}
	if err != nil {
		fmt.Printf("err: %v\n", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	if set.NArgs() != 1 {
		log.Fatal("Mandatory HOST:PORT argument missing")
	}
	s.hostAndPort = set.Arg(0)
}

type witness struct {
	signer crypto.Signer
	logPub crypto.PublicKey
	state  *state
}

func (s *witness) GetTreeSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		// TODO: Allowed header?
		http.Error(w, "Only GET supported", http.StatusBadRequest)
		return
	}
	slash := strings.LastIndex(r.URL.Path, "/")
	if slash < 0 {
		http.Error(w, "Invalid url", http.StatusBadRequest)
		return
	}
	keyHash, err := crypto.HashFromHex(r.URL.Path[slash+1:])
	if err != nil {
		http.Error(w, "Invalid keyhash url argument", http.StatusBadRequest)
		return
	}
	if keyHash != crypto.HashBytes(s.logPub[:]) {
		http.Error(w, "Unknown log keyhash", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := fmt.Fprintf(w, "size=%d\n", s.state.GetSize()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *witness) AddTreeHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		// TODO: Allowed header?
		http.Error(w, "Only POST supported", http.StatusBadRequest)
		return
	}
	var req requests.AddTreeHead
	if err := req.FromASCII(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logKeyHash := crypto.HashBytes(s.logPub[:])
	if req.KeyHash != logKeyHash {
		http.Error(w, "Unknown log keyhash", http.StatusNotFound)
		return
	}
	if !req.TreeHead.Verify(&s.logPub) {
		http.Error(w, "Invalid log signature", http.StatusForbidden)
		return
	}

	cs, status, err := s.state.Update(&req.TreeHead, req.OldSize, &req.Proof,
		func() (types.Cosignature, error) {
			return req.TreeHead.Cosign(s.signer, &logKeyHash, uint64(time.Now().Unix()))
		})
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	if err := cs.ToASCII(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type state struct {
	fileName string
	// Syncronizes all updates to both the size field and the
	// underlying file.
	m  sync.Mutex
	th types.TreeHead
}

func (s *state) Load(pub, logPub *crypto.PublicKey) error {
	f, err := os.Open(s.fileName)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.th = types.TreeHead{
			Size:     0,
			RootHash: crypto.HashBytes([]byte{}),
		}
		return nil
	}
	defer f.Close()

	var cth types.CosignedTreeHead
	if err := cth.FromASCII(f); err != nil {
		return err
	}
	if !cth.Verify(logPub) {
		return fmt.Errorf("Invalid log signature on stored tree head")
	}
	keyHash := crypto.HashBytes(pub[:])
	logKeyHash := crypto.HashBytes(logPub[:])
	for _, cs := range cth.Cosignatures {
		if cs.KeyHash != keyHash {
			continue
		}
		if cs.Verify(pub, &logKeyHash, &cth.TreeHead) {
			s.th = cth.SignedTreeHead.TreeHead
			return nil
		}
		return fmt.Errorf("Invalid cosignature on stored tree head")
	}
	return fmt.Errorf("No matching cosignature on stored tree head")
}

func (s *state) GetSize() uint64 {
	s.m.Lock()
	defer s.m.Unlock()
	return s.th.Size
}

// Must be called with lock held.
func (s *state) Store(cth *types.CosignedTreeHead) error {
	if cth.Size < s.th.Size {
		// TODO: Panic?
		return fmt.Errorf("cosigning an old tree, internal error")
	}
	tmpName := s.fileName + ".new"
	f, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	// In case Close is called explictly below, the deferred call
	// will fail, and error ignored.
	defer f.Close()
	defer os.Remove(tmpName) // Ignore error

	if err := cth.ToASCII(f); err != nil {
		return err
	}
	// Atomically replace old file with new.
	return os.Rename(tmpName, s.fileName)
}

// On success, returns stored cosignature. On failure, returns HTTP status code and error.
func (s *state) Update(sth *types.SignedTreeHead, oldSize uint64, proof *types.ConsistencyProof,
	cosign func() (types.Cosignature, error)) (types.Cosignature, int, error) {

	s.m.Lock()
	defer s.m.Unlock()

	if s.th.Size != oldSize {
		return types.Cosignature{}, http.StatusConflict, fmt.Errorf("incorrect old_size")
	}

	if err := proof.Verify(&s.th, &sth.TreeHead); err != nil {
		return types.Cosignature{}, 422, fmt.Errorf("not consistent")
	}

	cs, err := cosign()
	if err != nil {
		return types.Cosignature{}, http.StatusInternalServerError, err
	}
	cth := types.CosignedTreeHead{
		SignedTreeHead: *sth,
		Cosignatures:   []types.Cosignature{cs},
	}
	if err := s.Store(&cth); err != nil {
		return types.Cosignature{}, http.StatusInternalServerError, err
	}
	s.th = sth.TreeHead

	return cs, 0, nil
}
