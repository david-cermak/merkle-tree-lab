// get_sth retrieves the latest Signed Tree Head from the Trillian log.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	logAddr = flag.String("log_server", "localhost:8090", "Trillian Log server address (host:port)")
	treeID  = flag.Int64("tree_id", 0, "Tree ID (default: read from tree_id.txt)")
	output  = flag.String("output", "sth.json", "Output file for signed tree head")
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

	client := trillian.NewTrillianLogClient(conn)

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

	// Print to stdout
	fmt.Printf("Tree Size: %d\n", logRoot.TreeSize)
	fmt.Printf("Root Hash: %s\n", hex.EncodeToString(logRoot.RootHash))
	fmt.Printf("Timestamp: %d\n", logRoot.TimestampNanos)
	fmt.Printf("Signature: (log_root is TLS-serialized, signature removed in recent Trillian)\n")

	// Write JSON output
	sth := map[string]interface{}{
		"tree_size":    logRoot.TreeSize,
		"root_hash":    hex.EncodeToString(logRoot.RootHash),
		"timestamp":    logRoot.TimestampNanos,
		"log_root_b64": base64.StdEncoding.EncodeToString(resp.SignedLogRoot.LogRoot),
	}
	outData, _ := json.MarshalIndent(sth, "", "  ")
	if err := os.WriteFile(*output, outData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("\nWrote %s\n", *output)
}
