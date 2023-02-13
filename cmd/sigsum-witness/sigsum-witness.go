package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	endpointAddTreeHead = types.Endpoint("add-tree-head")
	endpointGetTreeSize = types.Endpoint("get-tree-size/")
)

type Settings struct {
	keyFile     string
	logKey      string
	stateFile   string
	prefix      string
	hostAndPort string
}

func main() {
	const usage = `sigsum-witness [OPTIONS] HOST:PORT
  Options:
      -h --help Display this help
      -k PRIVATE-KEY
      --log-key LOG-PUBLIC-KEY
      --state-file FILE
      --url-prefix PREFIX

  Provides a service for cosigning a sigsum log (currently, only a
  single log), listening on the given host and port.
`
	log.SetFlags(0)
	var settings Settings
	settings.parse(os.Args[1:], usage)

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

	http.HandleFunc("/"+endpointGetTreeSize.Path(settings.prefix), witness.GetTreeSize)
	http.HandleFunc("/"+endpointAddTreeHead.Path(settings.prefix), witness.AddTreeHead)
	log.Fatal(http.ListenAndServe(settings.hostAndPort, nil))
}

func (s *Settings) parse(args []string, usage string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	flags.StringVar(&s.keyFile, "k", "", "Witness private key")
	flags.StringVar(&s.logKey, "log-key", "", "Log public key")
	flags.StringVar(&s.stateFile, "state-file", "", "Name of state file")
	flags.StringVar(&s.prefix, "url-prefix", "", "Prefix preceing the endpoint names")
	flags.Parse(args)
	if len(s.keyFile) == 0 {
		log.Fatal("Mandatory -k flag missing")
	}
	if len(s.logKey) == 0 {
		log.Fatal("Mandatory --log-keyFile flag missing")
	}
	if len(s.stateFile) == 0 {
		log.Fatal("Mandatory --state-file flag missing")
	}
	if len(flags.Args()) != 1 {
		log.Fatal("Mandatory HOST:PORT argument missing")
	}
	s.hostAndPort = flags.Arg(0)
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
	}
	// TODO: Ignores extra url components. Requires lowercase.
	suffix := fmt.Sprintf("/%x", crypto.HashBytes(s.logPub[:]))
	if !strings.HasSuffix(r.URL.Path, suffix) {
		http.Error(w, "Log not known", http.StatusForbidden)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := fmt.Fprintf(w, "size=%d\n", s.state.GetSize()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *witness) AddTreeHead(w http.ResponseWriter, r *http.Request) {
}

type state struct {
	fileName string
	// Syncronizes all updates to both the size field and the
	// underlying file.
	m    sync.Mutex
	size uint64
}

func (s *state) Load(pub, logPub *crypto.PublicKey) error {
	f, err := os.Open(s.fileName)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		s.size = 0
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
			s.size = cth.Size
			return nil
		}
		return fmt.Errorf("Invalid cosignature on stored tree head")
	}
	return fmt.Errorf("No matching cosignature on stored tree head")
}

func (s *state) GetSize() uint64 {
	s.m.Lock()
	defer s.m.Unlock()
	return s.size
}

func (s *state) Store(cth *types.CosignedTreeHead) error {
	s.m.Lock()
	defer s.m.Unlock()

	if cth.Size < s.size {
		return fmt.Errorf("cosigning an old tree, log is misbehaving")
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
