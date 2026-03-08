package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/tosclient"
	"github.com/urfave/cli/v2"
)

var (
	voteJournalPathFlag = &cli.StringFlag{
		Name:     "journal",
		Usage:    "Checkpoint vote journal directory",
		Required: true,
	}
	voteEvidenceNumberFlag = &cli.Uint64Flag{
		Name:     "number",
		Usage:    "Checkpoint number of the malicious vote evidence",
		Required: true,
	}
	voteEvidenceSignerFlag = &cli.StringFlag{
		Name:     "signer",
		Usage:    "Validator signer address",
		Required: true,
	}
	voteEvidenceOutFlag = &cli.StringFlag{
		Name:  "out",
		Usage: "Output path (default: stdout)",
	}
	voteEvidenceFileFlag = &cli.StringFlag{
		Name:     "evidence",
		Usage:    "Path to an existing malicious vote evidence file",
		Required: true,
	}
	voteEvidenceOutboxFlag = &cli.StringFlag{
		Name:     "outbox",
		Usage:    "Directory used to stage evidence for future submission",
		Required: true,
	}
	voteRPCURLFlag = &cli.StringFlag{
		Name:  "rpc",
		Usage: "TOS RPC endpoint used for evidence submission",
		Value: "http://localhost:8545",
	}
	voteFromFlag = &cli.StringFlag{
		Name:     "from",
		Usage:    "Submitter account address",
		Required: true,
	}
	voteCommand = &cli.Command{
		Name:  "vote",
		Usage: "Checkpoint vote evidence operations",
		Subcommands: []*cli.Command{
			{
				Name:  "export-evidence",
				Usage: "Export canonical malicious-vote evidence from a vote journal",
				Flags: []cli.Flag{
					voteJournalPathFlag,
					voteEvidenceNumberFlag,
					voteEvidenceSignerFlag,
					voteEvidenceOutFlag,
				},
				Action: exportVoteEvidence,
			},
			{
				Name:  "stage-evidence",
				Usage: "Validate and stage malicious-vote evidence in a standard outbox path",
				Flags: []cli.Flag{
					voteEvidenceFileFlag,
					voteEvidenceOutboxFlag,
				},
				Action: stageVoteEvidence,
			},
			{
				Name:  "submit-evidence",
				Usage: "Validate and submit malicious-vote evidence on-chain via RPC",
				Flags: []cli.Flag{
					voteEvidenceFileFlag,
					voteRPCURLFlag,
					voteFromFlag,
				},
				Action: submitVoteEvidence,
			},
		},
	}
)

func exportVoteEvidence(ctx *cli.Context) error {
	signer := common.HexToAddress(ctx.String(voteEvidenceSignerFlag.Name))
	evidence, err := dpos.ExportMaliciousVoteEvidence(
		ctx.String(voteJournalPathFlag.Name),
		ctx.Uint64(voteEvidenceNumberFlag.Name),
		signer,
	)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if out := ctx.String(voteEvidenceOutFlag.Name); out != "" {
		return os.WriteFile(out, data, 0o644)
	}
	_, err = os.Stdout.Write(data)
	return err
}

func stageVoteEvidence(ctx *cli.Context) error {
	data, err := os.ReadFile(ctx.String(voteEvidenceFileFlag.Name))
	if err != nil {
		return err
	}
	var evidence types.MaliciousVoteEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return err
	}
	path, err := dpos.StageMaliciousVoteEvidence(&evidence, ctx.String(voteEvidenceOutboxFlag.Name))
	if err != nil {
		return err
	}
	fmt.Printf("staged malicious vote evidence: %s\n", path)
	fmt.Printf("evidence hash: %s\n", evidence.Hash().Hex())
	return nil
}

func submitVoteEvidence(ctx *cli.Context) error {
	data, err := os.ReadFile(ctx.String(voteEvidenceFileFlag.Name))
	if err != nil {
		return err
	}
	var evidence types.MaliciousVoteEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return err
	}
	if err := evidence.Validate(); err != nil {
		return err
	}
	client, err := tosclient.Dial(ctx.String(voteRPCURLFlag.Name))
	if err != nil {
		return err
	}
	defer client.Close()

	from := common.HexToAddress(ctx.String(voteFromFlag.Name))
	txHash, err := client.SubmitMaliciousVoteEvidence(ctx.Context, tosclient.SubmitMaliciousVoteEvidenceArgs{
		From:     from,
		Evidence: evidence,
	})
	if err != nil {
		return err
	}
	fmt.Printf("submitted malicious vote evidence tx: %s\n", txHash.Hex())
	fmt.Printf("evidence hash: %s\n", evidence.Hash().Hex())
	return nil
}
