// get_proof retrieves an inclusion proof for a leaf in the Trillian log.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	logAddr   = flag.String("log_server", "localhost:8090", "Trillian Log server address (host:port)")
	treeID    = flag.Int64("tree_id", 0, "Tree ID (default: read from tree_id.txt)")
	leafIndex = flag.Int64("leaf_index", -1, "Leaf index (default: read from leaf_index.txt)")
	treeSize  = flag.Int64("tree_size", 0, "Tree size at which to get proof (default: use latest)")
	certFile  = flag.String("cert", "", "Certificate file to get proof for (computes leaf hash from DER)")
	output    = flag.String("output", "proof.json", "Output file for inclusion proof")
)

func readTreeID() (int64, error) {
	if *treeID != 0 {
		return *treeID, nil
	}
	data, err := os.ReadFile("tree_id.txt")
	if err != nil {
		return 0, fmt.Errorf("read tree_id.txt: %w", err)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse tree_id: %w", err)
	}
	return id, nil
}

func readLeafIndex() (int64, error) {
	if *leafIndex >= 0 {
		return *leafIndex, nil
	}
	data, err := os.ReadFile("leaf_index.txt")
	if err != nil {
		return 0, fmt.Errorf("read leaf_index.txt: %w", err)
	}
	idx, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse leaf_index: %w", err)
	}
	return idx, nil
}

func leafHashFromCert(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Extract DER from PEM
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			// RFC6962 leaf hash: H(0x00 || leaf_value)
			hasher := rfc6962.DefaultHasher
			return hasher.HashLeaf(block.Bytes), nil
		}
	}
	return nil, fmt.Errorf("no certificate in %s", path)
}

func main() {
	flag.Parse()

	tid, err := readTreeID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get tree ID: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.Dial(*logAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	logClient := trillian.NewTrillianLogClient(conn)

	var leafHash []byte
	var idx int64

	if *certFile != "" {
		leafHash, err = leafHashFromCert(*certFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get leaf hash from cert: %v\n", err)
			os.Exit(1)
		}
		// GetInclusionProofByHash - we need tree size
		if *treeSize == 0 {
			resp, err := logClient.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{LogId: tid})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get latest root: %v\n", err)
				os.Exit(1)
			}
			var logRoot types.LogRootV1
			if err := logRoot.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse log root: %v\n", err)
				os.Exit(1)
			}
			*treeSize = int64(logRoot.TreeSize)
		}
	} else {
		idx, err = readLeafIndex()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get leaf index: %v\n", err)
			os.Exit(1)
		}
		// Get tree size if not specified
		if *treeSize == 0 {
			resp, err := logClient.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{LogId: tid})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get latest root: %v\n", err)
				os.Exit(1)
			}
			var logRoot types.LogRootV1
			if err := logRoot.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse log root: %v\n", err)
				os.Exit(1)
			}
			*treeSize = int64(logRoot.TreeSize)
		}
		// Get leaf hash from GetEntryAndProof
		entryResp, err := logClient.GetEntryAndProof(ctx, &trillian.GetEntryAndProofRequest{
			LogId:     tid,
			LeafIndex: idx,
			TreeSize:  *treeSize,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetEntryAndProof failed: %v\n", err)
			os.Exit(1)
		}
		leafHash = entryResp.Leaf.MerkleLeafHash
		if len(leafHash) == 0 {
			hasher := rfc6962.DefaultHasher
			leafHash = hasher.HashLeaf(entryResp.Leaf.LeafValue)
		}
		idx = entryResp.Leaf.LeafIndex
	}

	// Use GetInclusionProofByHash for cert-based lookup, GetInclusionProof for index-based
	var proof *trillian.Proof
	if *certFile != "" {
		resp, err := logClient.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
			LogId:     tid,
			LeafHash:  leafHash,
			TreeSize:  *treeSize,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetInclusionProofByHash failed: %v\n", err)
			os.Exit(1)
		}
		if len(resp.Proof) == 0 {
			fmt.Fprintf(os.Stderr, "No proof returned (leaf may not be sequenced yet)\n")
			os.Exit(1)
		}
		proof = resp.Proof[0]
	} else {
		resp, err := logClient.GetInclusionProof(ctx, &trillian.GetInclusionProofRequest{
			LogId:     tid,
			LeafIndex: idx,
			TreeSize:  *treeSize,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetInclusionProof failed: %v\n", err)
			os.Exit(1)
		}
		proof = resp.Proof
	}

	auditPath := make([]string, len(proof.Hashes))
	for i, h := range proof.Hashes {
		auditPath[i] = hex.EncodeToString(h)
	}

	out := map[string]interface{}{
		"leaf_hash":  hex.EncodeToString(leafHash),
		"leaf_index": proof.LeafIndex,
		"tree_size":  *treeSize,
		"audit_path": auditPath,
	}

	outData, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(*output, outData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("Proof written to %s\n", *output)
	fmt.Printf("Leaf index: %d, Tree size: %d, Audit path length: %d\n",
		proof.LeafIndex, *treeSize, len(auditPath))
}
