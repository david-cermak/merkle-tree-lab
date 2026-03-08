// create_tree creates a Trillian LOG tree and saves the tree ID to tree_id.txt.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	adminAddr = flag.String("admin_server", "localhost:8090", "Trillian Admin server address (host:port)")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.Dial(*adminAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to %s: %v\n", *adminAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	adminClient := trillian.NewTrillianAdminClient(conn)
	logClient := trillian.NewTrillianLogClient(conn)

	req := &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			DisplayName:     "Merkle Certificate Log",
			Description:     "Transparency log for certificate inclusion proofs",
			MaxRootDuration: durationpb.New(time.Hour),
		},
	}

	tree, err := client.CreateAndInitTree(ctx, req, adminClient, logClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create tree: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("tree_id.txt", []byte(fmt.Sprintf("%d\n", tree.TreeId)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write tree_id.txt: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created tree ID: %d (saved to tree_id.txt)\n", tree.TreeId)
}
