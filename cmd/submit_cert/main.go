// submit_cert reads certificates and submits them to the Trillian log as leaves.
// Each certificate's DER encoding becomes the leaf value.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	logAddr    = flag.String("log_server", "localhost:8090", "Trillian Log server address (host:port)")
	treeID     = flag.Int64("tree_id", 0, "Tree ID (default: read from tree_id.txt)")
	certDir    = flag.String("certs", "certs", "Directory containing cert-N.pem files")
	outputFile = flag.String("output", "leaf_index.txt", "File to write the last submitted leaf index")
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

func loadCertDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.Raw, nil
}

func main() {
	flag.Parse()

	tid, err := readTreeID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get tree ID: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	conn, err := grpc.Dial(*logAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := trillian.NewTrillianLogClient(conn)

	// Find all cert files
	entries, err := os.ReadDir(*certDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read certs dir: %v\n", err)
		os.Exit(1)
	}

	var certPaths []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "cert-") && strings.HasSuffix(e.Name(), ".pem") {
			certPaths = append(certPaths, filepath.Join(*certDir, e.Name()))
		}
	}

	if len(certPaths) == 0 {
		fmt.Fprintf(os.Stderr, "No certificates found in %s\n", *certDir)
		os.Exit(1)
	}

	// Submit each certificate
	for i, path := range certPaths {
		der, err := loadCertDER(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", path, err)
			os.Exit(1)
		}

		_, err = client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
			LogId: tid,
			Leaf: &trillian.LogLeaf{
				LeafValue: der,
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "QueueLeaf failed: %v\n", err)
			os.Exit(1)
		}
		if (i+1)%10 == 0 || i == 0 {
			fmt.Printf("Submitted %d/%d certificates...\n", i+1, len(certPaths))
		}
	}

	fmt.Printf("Submitted %d certificates. Waiting for sequencing...\n", len(certPaths))

	// Wait for all leaves to be sequenced
	expectedSize := int64(len(certPaths))
	for {
		resp, err := client.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{LogId: tid})
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetLatestSignedLogRoot failed: %v\n", err)
			os.Exit(1)
		}

		var logRoot types.LogRootV1
		if err := logRoot.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse log root: %v\n", err)
			os.Exit(1)
		}

		if logRoot.TreeSize >= uint64(expectedSize) {
			fmt.Printf("Tree size: %d\n", logRoot.TreeSize)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	lastIndex := int64(len(certPaths)) - 1
	if err := os.WriteFile(*outputFile, []byte(fmt.Sprintf("%d\n", lastIndex)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("Last leaf index: %d (saved to %s)\n", lastIndex, *outputFile)
}
