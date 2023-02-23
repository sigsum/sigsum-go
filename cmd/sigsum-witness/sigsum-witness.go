package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/ascii"
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

type TreeHeadRequest struct {
	KeyHash  crypto.Hash
	TreeHead types.SignedTreeHead
	OldSize  uint64
	Path     []crypto.Hash
}

func (req *TreeHeadRequest) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	req.KeyHash, err = p.GetHash("key_hash")
	if err != nil {
		return err
	}
	if err := req.TreeHead.Parse(&p); err != nil {
		return err
	}
	req.OldSize, err = p.GetInt("old_size")
	if err != nil {
		return err
	}
	if req.OldSize > req.TreeHead.Size {
		return fmt.Errorf("invalid request, old_size(%d) > size(%d)",
			req.OldSize, req.TreeHead.Size)
	}
	// Cases of trivial consistency.
	if req.OldSize == 0 || req.OldSize == req.TreeHead.Size {
		return p.GetEOF()
	}
	req.Path, err = types.HashesFromASCII(&p)
	return err
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
	if r.Method != "POST" {
		// TODO: Allowed header?
		http.Error(w, "Only POST supported", http.StatusBadRequest)
		return
	}
	var req TreeHeadRequest
	if err := req.FromASCII(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logKeyHash := crypto.HashBytes(s.logPub[:])
	if req.KeyHash != logKeyHash {
		http.Error(w, "unknown log", http.StatusForbidden)
		return
	}
	if !req.TreeHead.Verify(&s.logPub) {
		http.Error(w, "invalid log signatrue", http.StatusForbidden)
		return
	}

	cs, status, err := s.state.Update(&req.TreeHead, req.OldSize, req.Path,
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
		if !errors.Is(err, fs.ErrNotExist) {
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
func (s *state) Update(sth *types.SignedTreeHead, oldSize uint64, path []crypto.Hash,
	cosign func() (types.Cosignature, error)) (types.Cosignature, int, error) {

	s.m.Lock()
	defer s.m.Unlock()

	if s.th.Size != oldSize {
		return types.Cosignature{}, http.StatusConflict, fmt.Errorf("incorrect old_size")
	}

	pr := types.ConsistencyProof{OldSize: oldSize, NewSize: sth.Size, Path: path}
	if err := pr.Verify(&s.th.RootHash, &sth.RootHash); err != nil {
		return types.Cosignature{}, 444, fmt.Errorf("not consistent")
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
