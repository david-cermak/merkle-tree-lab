// Command witness is a minimal local tlog-witness server for the workshop.
//
// It exists so the lab can demonstrate native TesseraCT witnessing offline,
// without registering a key with the public witness network.
//
// Subcommands:
//
//	witness keygen --name NAME --out FILE
//	    Generate an Ed25519 note key, write the private key to FILE, and print
//	    two verifier keys: the plain one (used by the witness to trust a log)
//	    and the CosignatureV1 one (used in the log's witness policy).
//
//	witness serve --listen ADDR --signer-key FILE --log-vkey FILE
//	    Serve the tlog-witness add-checkpoint API, cosigning checkpoints that
//	    are validly signed by the trusted log key.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/persistence/inmemory"
	"github.com/transparency-dev/witness/witness"
	"golang.org/x/mod/sumdb/note"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  witness keygen --name NAME --out FILE
  witness serve  --listen ADDR --signer-key FILE --log-vkey FILE
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	default:
		usage()
	}
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "", "key name (witness or log origin)")
	out := fs.String("out", "", "file to write the private key to")
	_ = fs.Parse(args)
	if *name == "" || *out == "" {
		fs.Usage()
		os.Exit(2)
	}

	skey, vkey, err := note.GenerateKey(rand.Reader, *name)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	if err := os.WriteFile(*out, []byte(skey+"\n"), 0o600); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	cosigVkey, err := f_note.VKeyToCosignatureV1(vkey)
	if err != nil {
		log.Fatalf("convert to cosignature v1 key: %v", err)
	}
	// Line 1: plain verifier (trust a log). Line 2: cosignature verifier (policy).
	fmt.Println(vkey)
	fmt.Println(cosigVkey)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8100", "address to listen on")
	signerKeyPath := fs.String("signer-key", "", "witness private key file (note format)")
	logVkeyPath := fs.String("log-vkey", "", "trusted log verifier key file")
	_ = fs.Parse(args)
	if *signerKeyPath == "" || *logVkeyPath == "" {
		fs.Usage()
		os.Exit(2)
	}

	signerKey, err := os.ReadFile(*signerKeyPath)
	if err != nil {
		log.Fatalf("read signer key: %v", err)
	}
	logVkey, err := os.ReadFile(*logVkeyPath)
	if err != nil {
		log.Fatalf("read log verifier key: %v", err)
	}

	signer, err := f_note.NewSignerForCosignatureV1(strings.TrimSpace(string(signerKey)))
	if err != nil {
		log.Fatalf("load cosignature signer: %v", err)
	}
	logVerifier, err := note.NewVerifier(strings.TrimSpace(string(logVkey)))
	if err != nil {
		log.Fatalf("load log verifier: %v", err)
	}

	w, err := witness.New(context.Background(), witness.Opts{
		Persistence: inmemory.New(),
		Signers:     []note.Signer{signer},
		VerifierForLog: func(_ context.Context, _ string) (note.Verifier, bool, error) {
			return logVerifier, true, nil
		},
	})
	if err != nil {
		log.Fatalf("create witness: %v", err)
	}

	handler := witness.NewHTTPHandler(w)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", handler.AddCheckpoint)
	mux.HandleFunc("GET /key", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(rw, signer.Verifier().Name())
	})

	log.Printf("witness listening on %s (trusting log %q)", *listen, logVerifier.Name())
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
