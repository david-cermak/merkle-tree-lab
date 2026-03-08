// verify_proof verifies that a certificate is included in the log using the
// inclusion proof and signed tree head.
package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	certFile  = flag.String("cert", "certs/cert-0.pem", "Certificate file (PEM)")
	proofFile = flag.String("proof", "proof.json", "Inclusion proof JSON file")
	sthFile   = flag.String("sth", "sth.json", "Signed tree head JSON file")
)

func main() {
	flag.Parse()

	// Load certificate
	certData, err := os.ReadFile(*certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read cert: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Fprintf(os.Stderr, "No certificate found in %s\n", *certFile)
		os.Exit(1)
	}
	certDER := block.Bytes

	// Compute leaf hash (RFC6962: H(0x00 || leaf_value))
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(certDER)

	// Load proof
	proofData, err := os.ReadFile(*proofFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read proof: %v\n", err)
		os.Exit(1)
	}

	var proof struct {
		LeafHash  string   `json:"leaf_hash"`
		LeafIndex int64    `json:"leaf_index"`
		TreeSize  int64    `json:"tree_size"`
		AuditPath []string `json:"audit_path"`
	}
	if err := json.Unmarshal(proofData, &proof); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse proof: %v\n", err)
		os.Exit(1)
	}

	auditPath := make([][]byte, len(proof.AuditPath))
	for i, h := range proof.AuditPath {
		auditPath[i], err = hex.DecodeString(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid audit path hash: %v\n", err)
			os.Exit(1)
		}
	}

	// Load STH
	sthData, err := os.ReadFile(*sthFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read STH: %v\n", err)
		os.Exit(1)
	}

	var sth struct {
		TreeSize   uint64 `json:"tree_size"`
		RootHash   string `json:"root_hash"`
		LogRootB64 string `json:"log_root_b64"`
	}
	if err := json.Unmarshal(sthData, &sth); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse STH: %v\n", err)
		os.Exit(1)
	}

	rootHash, err := hex.DecodeString(sth.RootHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid root hash: %v\n", err)
		os.Exit(1)
	}

	trustedRoot := &types.LogRootV1{
		TreeSize:       sth.TreeSize,
		RootHash:       rootHash,
		TimestampNanos: 0,
	}

	verifier := client.NewLogVerifier(rfc6962.DefaultHasher)
	trillianProof := &trillian.Proof{
		LeafIndex: proof.LeafIndex,
		Hashes:    auditPath,
	}

	if err := verifier.VerifyInclusionByHash(trustedRoot, leafHash, trillianProof); err != nil {
		fmt.Fprintf(os.Stderr, "Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Certificate inclusion verified")
}
