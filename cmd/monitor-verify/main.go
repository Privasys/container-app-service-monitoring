// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Command monitor-verify checks a monitor's evidence without the
// monitor.
//
// It ships inside the same image so an operator can hand a counterparty
// a binary that checks the record rather than an invitation to trust
// it. Nothing here contacts anything: every subcommand reads files and
// a public key.
//
//	monitor-verify bundle   evidence.json  --key key.json
//	monitor-verify chain    chain.json     --key key.json
//	monitor-verify lineage  lineage.json
//	monitor-verify report   report.json    --key key.json
//
// The one that matters most is `report`. It does not check that a
// number was signed; it recomputes the number from the readings the
// document carries and requires the two to agree, and it looks for
// downtime in the evidence that the report failed to declare. A signed
// wrong answer fails here.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/checkpoint"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}
	command, path := os.Args[1], os.Args[2]

	flags := flag.NewFlagSet(command, flag.ExitOnError)
	keyPath := flags.String("key", "", "a key document from GET /api/v1/checkpoints/key")
	pubKey := flags.String("public-key", "", "the base64 verification key, instead of --key")
	quiet := flags.Bool("quiet", false, "print nothing; report the result in the exit status")
	if err := flags.Parse(os.Args[3:]); err != nil {
		os.Exit(2)
	}

	pub, err := loadKey(*keyPath, *pubKey)
	if err != nil && command != "lineage" {
		fail(*quiet, err)
	}

	var checks []check
	switch command {
	case "bundle":
		checks, err = verifyBundle(path, pub)
	case "chain":
		checks, err = verifyChain(path, pub)
	case "lineage":
		checks, err = verifyLineage(path, pub)
	case "report":
		checks, err = verifyReport(path, pub)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fail(*quiet, err)
	}

	failed := 0
	for _, c := range checks {
		if !c.ok {
			failed++
		}
		if !*quiet {
			mark := "ok  "
			if !c.ok {
				mark = "FAIL"
			}
			fmt.Printf("%s  %s: %s\n", mark, c.name, c.detail)
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
monitor-verify checks a Privasys service monitor's evidence offline.

  monitor-verify bundle  <evidence.json> --key <key.json>
  monitor-verify chain   <chain.json>    --key <key.json>
  monitor-verify lineage <lineage.json>
  monitor-verify report  <report.json>   --key <key.json>
`))
}

type check struct {
	name   string
	detail string
	ok     bool
}

func pass(name, detail string) check { return check{name: name, detail: detail, ok: true} }
func fault(name, detail string) check {
	return check{name: name, detail: detail, ok: false}
}

func fail(quiet bool, err error) {
	if !quiet {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(1)
}

func loadKey(keyPath, inline string) (ed25519.PublicKey, error) {
	if inline != "" {
		return checkpoint.ParsePublicKey(inline)
	}
	if keyPath == "" {
		return nil, fmt.Errorf("a verification key is required (--key or --public-key)")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	var doc struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("key document: %w", err)
	}
	return checkpoint.ParsePublicKey(doc.PublicKey)
}

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// -- bundle ----------------------------------------------------------------

func verifyBundle(path string, pub ed25519.PublicKey) ([]check, error) {
	var bundle model.EvidenceBundle
	if err := readJSON(path, &bundle); err != nil {
		return nil, err
	}
	var checks []check

	if err := checkpoint.VerifyBundleProof(&bundle); err != nil {
		checks = append(checks, fault("inclusion proof", err.Error()))
	} else {
		checks = append(checks, pass("inclusion proof",
			fmt.Sprintf("folds to root %s and shows the entry %s",
				short(bundle.Root), presence(bundle.Present))))
	}

	if err := checkpoint.VerifyBundleSignature(pub, &bundle); err != nil {
		checks = append(checks, fault("signature", err.Error()))
	} else {
		checks = append(checks, pass("signature", "signed by key "+short(bundle.KeyID)))
	}

	if bundle.Checkpoint == nil {
		checks = append(checks, fault("anchor", "the bundle carries no checkpoint"))
		return checks, nil
	}
	if err := checkpoint.VerifyCheckpoint(pub, bundle.Checkpoint); err != nil {
		checks = append(checks, fault("anchor", err.Error()))
	} else if err := checkpoint.VerifyBundleAgainstCheckpoint(&bundle, &bundle.Checkpoint.Checkpoint); err != nil {
		checks = append(checks, fault("anchor", err.Error()))
	} else {
		checks = append(checks, pass("anchor",
			fmt.Sprintf("version %d is the state the checkpoint attests", bundle.Version)))
	}
	return checks, nil
}

func presence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

// -- chain -----------------------------------------------------------------

func verifyChain(path string, pub ed25519.PublicKey) ([]check, error) {
	var doc struct {
		Checkpoints []*model.SignedCheckpoint `json:"checkpoints"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, err
	}
	if len(doc.Checkpoints) == 0 {
		return nil, fmt.Errorf("the document holds no checkpoints")
	}
	chain := append([]*model.SignedCheckpoint(nil), doc.Checkpoints...)
	sort.Slice(chain, func(i, j int) bool {
		return chain[i].Checkpoint.Version < chain[j].Checkpoint.Version
	})

	var checks []check
	bad := 0
	for _, signed := range chain {
		if err := checkpoint.VerifyCheckpoint(pub, signed); err != nil {
			bad++
			checks = append(checks, fault(fmt.Sprintf("checkpoint %d", signed.Checkpoint.Version), err.Error()))
		}
	}
	if bad == 0 {
		checks = append(checks, pass("signatures",
			fmt.Sprintf("%d checkpoints, all signed by key %s", len(chain), short(chain[0].KeyID))))
	}

	// Each link names the one before it. A monitor that served two
	// histories has to have signed both, and the fork shows up here as a
	// link that does not match.
	broken := 0
	for i := 1; i < len(chain); i++ {
		prev, cur := chain[i-1].Checkpoint, chain[i].Checkpoint
		if cur.Previous == nil {
			broken++
			checks = append(checks, fault(fmt.Sprintf("link at %d", cur.Version),
				"the checkpoint names no predecessor"))
			continue
		}
		if cur.Previous.Version != prev.Version || cur.Previous.Root != prev.Root {
			broken++
			checks = append(checks, fault(fmt.Sprintf("link at %d", cur.Version),
				fmt.Sprintf("names version %d root %s, the previous checkpoint is version %d root %s",
					cur.Previous.Version, short(cur.Previous.Root), prev.Version, short(prev.Root))))
		}
	}
	if broken == 0 && len(chain) > 1 {
		checks = append(checks, pass("chain", "every checkpoint names the one before it"))
	}
	return checks, nil
}

// -- lineage ---------------------------------------------------------------

// verifyLineage is the check an auditor actually runs, because it needs
// no key at all. Two anchors and the public roots between them are
// folded forward with a pure function, and the result has to arrive at
// the later anchor's head. A record that was rewritten in between
// cannot reach it: doing so would be a preimage attack.
func verifyLineage(path string, pub ed25519.PublicKey) ([]check, error) {
	var doc model.Lineage
	if err := readJSON(path, &doc); err != nil {
		return nil, err
	}
	if doc.From == nil || doc.To == nil {
		return nil, fmt.Errorf("the document needs a from and a to anchor")
	}
	var checks []check

	if pub != nil {
		bad := false
		for name, anchor := range map[string]*model.SignedCheckpoint{"from": doc.From, "to": doc.To} {
			if err := checkpoint.VerifyCheckpoint(pub, anchor); err != nil {
				checks = append(checks, fault("anchor "+name, err.Error()))
				bad = true
			}
		}
		if !bad {
			checks = append(checks, pass("anchors", "both anchors are signed"))
		}
	}

	head, err := parseHash(doc.From.Checkpoint.Head)
	if err != nil {
		return nil, fmt.Errorf("the from anchor carries no lineage head: %w", err)
	}
	root, err := parseHash(doc.From.Checkpoint.Root)
	if err != nil {
		return nil, err
	}

	roots := append([]model.RootAt(nil), doc.Roots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].Version < roots[j].Version })

	version := doc.From.Checkpoint.Version
	for _, entry := range roots {
		if entry.Version != version+1 {
			return append(checks, fault("lineage",
				fmt.Sprintf("the roots skip from version %d to %d", version, entry.Version))), nil
		}
		head = ledger.HistoryLink(head, root, entry.Version)
		root, err = parseHash(entry.Root)
		if err != nil {
			return nil, err
		}
		version = entry.Version
	}

	if version != doc.To.Checkpoint.Version {
		return append(checks, fault("lineage",
			fmt.Sprintf("the roots end at version %d, the anchor is at %d",
				version, doc.To.Checkpoint.Version))), nil
	}
	want, err := parseHash(doc.To.Checkpoint.Head)
	if err != nil {
		return nil, fmt.Errorf("the to anchor carries no lineage head: %w", err)
	}
	if head != want {
		return append(checks, fault("lineage",
			fmt.Sprintf("the roots fold to %s, the anchor claims %s",
				short(hex.EncodeToString(head[:])), short(doc.To.Checkpoint.Head)))), nil
	}
	return append(checks, pass("lineage",
		fmt.Sprintf("%d roots fold from version %d to the head anchored at %d",
			len(roots), doc.From.Checkpoint.Version, doc.To.Checkpoint.Version))), nil
}

func parseHash(encoded string) (ledger.Hash, error) {
	var out ledger.Hash
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// -- report ----------------------------------------------------------------

// verifyReport recomputes the document rather than checking that it was
// signed.
//
// Five things are established, and the last two are the ones a supplier
// cannot talk their way around: the arithmetic in the report is what
// its own readings imply, and there is no downtime in those readings
// that the report failed to declare.
func verifyReport(path string, pub ed25519.PublicKey) ([]check, error) {
	var report model.Report
	if err := readJSON(path, &report); err != nil {
		return nil, err
	}
	if report.Evidence == nil {
		return nil, fmt.Errorf("the report carries no evidence; ask for it with the evidence attached")
	}
	var checks []check

	if err := core.VerifyReportSignature(pub, &report); err != nil {
		checks = append(checks, fault("signature", err.Error()))
	} else {
		checks = append(checks, pass("signature", "signed by key "+short(report.KeyID)))
	}

	// The evidence hash binds the readings to the row the ledger holds,
	// so a friendlier set cannot be substituted after the fact.
	recomputed := core.EvidenceHash(report.Evidence.Buckets)
	if recomputed != report.Evidence.EvidenceHash {
		checks = append(checks, fault("evidence commitment",
			fmt.Sprintf("the readings hash to %s, the report commits to %s",
				short(recomputed), short(report.Evidence.EvidenceHash))))
	} else {
		checks = append(checks, pass("evidence commitment",
			fmt.Sprintf("%d folded intervals hash to the committed value", len(report.Evidence.Buckets))))
	}

	// The report row is in the ledger, and the document is the bytes
	// that row commits to.
	rowChecks, row := verifyReportRow(&report, pub)
	checks = append(checks, rowChecks...)
	if row != nil {
		if hash, ok := row["evidence_hash"].(string); ok && hash != report.Evidence.EvidenceHash {
			checks = append(checks, fault("row commitment",
				"the recorded row commits to a different set of readings"))
		}
	}

	// The arithmetic, recomputed.
	out, err := recompute(&report)
	if err != nil {
		return append(checks, fault("arithmetic", err.Error())), nil
	}
	checks = append(checks, compare("agreed service time", out.AST.Net, report.AST.Net)...)
	checks = append(checks, compare("downtime", out.Downtime.Seconds, report.Downtime.Seconds)...)
	checks = append(checks, compare("availability", out.Results.AvailabilityPPM,
		report.Results.AvailabilityPPM)...)
	checks = append(checks, compare("user-weighted availability", out.Results.UserAvailabilityPPM,
		report.Results.UserAvailabilityPPM)...)
	checks = append(checks, compare("coverage", out.Results.CoveragePPM, report.Results.CoveragePPM)...)

	for _, want := range report.Objectives {
		found := false
		for _, got := range out.Objectives {
			if got.ID != want.ID {
				continue
			}
			found = true
			if got.Result != want.Result || got.AchievedPPM != want.AchievedPPM {
				checks = append(checks, fault("objective "+want.Name,
					fmt.Sprintf("the report says %s at %s, the evidence gives %s at %s",
						want.Result, availability.FormatPPM(want.AchievedPPM),
						got.Result, availability.FormatPPM(got.AchievedPPM))))
			} else {
				checks = append(checks, pass("objective "+want.Name,
					fmt.Sprintf("%s at %s", got.Result, availability.FormatPPM(got.AchievedPPM))))
			}
		}
		if !found {
			checks = append(checks, fault("objective "+want.Name, "not reproducible from the evidence"))
		}
	}

	// Undeclared downtime. This is the check that matters in an
	// argument: every interval the readings show as down has to appear
	// in the report as an outage.
	checks = append(checks, undeclared(&report, out)...)
	return checks, nil
}

func verifyReportRow(report *model.Report, pub ed25519.PublicKey) ([]check, map[string]any) {
	var checks []check
	var row map[string]any
	for i := range report.Evidence.Proofs {
		bundle := report.Evidence.Proofs[i]
		if bundle.Table != "reports" {
			continue
		}
		if err := checkpoint.VerifyBundleProof(&bundle); err != nil {
			return append(checks, fault("recorded row", err.Error())), nil
		}
		if err := checkpoint.VerifyBundleSignature(pub, &bundle); err != nil {
			return append(checks, fault("recorded row", err.Error())), nil
		}
		row = bundle.Row
		checks = append(checks, pass("recorded row",
			fmt.Sprintf("the report is a row in the state rooted at %s", short(bundle.Root))))

		// The document minus its evidence and signature is what the row
		// carries, so the numbers cannot have been edited after the
		// record was written.
		body, err := core.ReportCoreBytes(report)
		if err == nil {
			if stored, ok := row["document"]; ok {
				if !sameDocument(stored, body) {
					checks = append(checks, fault("document",
						"the document does not match the one recorded in the ledger"))
				} else {
					checks = append(checks, pass("document",
						"matches the document recorded in the ledger"))
				}
			}
		}
		if bundle.Checkpoint != nil {
			if err := checkpoint.VerifyCheckpoint(pub, bundle.Checkpoint); err != nil {
				checks = append(checks, fault("anchor", err.Error()))
			} else {
				checks = append(checks, pass("anchor",
					fmt.Sprintf("version %d is the state a signed checkpoint attests", bundle.Version)))
			}
		}
		return checks, row
	}
	return append(checks, fault("recorded row", "the report carries no proof of its own row")), nil
}

// sameDocument compares the stored column against the canonical bytes.
// The column arrives from JSON as a base64 string or as text depending
// on the route it took, so both are accepted and compared as bytes.
func sameDocument(stored any, want []byte) bool {
	switch v := stored.(type) {
	case string:
		if v == string(want) {
			return true
		}
		if decoded, err := decodeBase64(v); err == nil {
			return string(decoded) == string(want)
		}
	}
	return false
}

func recompute(report *model.Report) (availability.Output, error) {
	byComponent := map[string][]model.Bucket{}
	for _, b := range report.Evidence.Buckets {
		byComponent[b.ComponentID] = append(byComponent[b.ComponentID], b)
	}
	in := availability.Input{
		Period: report.Period, Scheduled: report.AST.Intervals,
		Exclusions: report.Exclusions,
	}
	// The coverage floor is not carried on the report as a field; it is
	// implied by the objective results, so the recomputation applies the
	// same rule by reading it back from an indeterminate verdict.
	in.CoverageFloorPPM = impliedFloor(report)
	for _, c := range report.Components {
		in.Components = append(in.Components, availability.ComponentInput{
			ID: c.ComponentID, Name: c.Name, UserWeight: c.UserWeight,
			Rollup: c.Rollup, Buckets: byComponent[c.ComponentID],
		})
	}
	for _, o := range report.Objectives {
		in.Objectives = append(in.Objectives, model.Objective{
			ID: o.ID, Name: o.Name, Metric: o.Metric,
			TargetPPM: o.TargetPPM, Window: o.Window,
		})
	}
	return availability.Compute(in)
}

// impliedFloor recovers the coverage floor the report was evaluated
// against. A report that declared an objective indeterminate for
// coverage states the floor in the reason; otherwise the floor cannot
// have bitten, and zero reproduces the same verdicts.
func impliedFloor(report *model.Report) int64 {
	for _, o := range report.Objectives {
		if o.Result != model.ObjectiveIndeterminate {
			continue
		}
		if idx := strings.Index(o.Reason, "below the "); idx >= 0 {
			var whole, frac int64
			if _, err := fmt.Sscanf(o.Reason[idx+len("below the "):], "%d.%d%%", &whole, &frac); err == nil {
				return whole*10000 + frac*10
			}
		}
	}
	return 0
}

func compare(name string, got, want int64) []check {
	if got == want {
		return []check{pass(name, fmt.Sprintf("%d, recomputed from the evidence", want))}
	}
	return []check{fault(name, fmt.Sprintf("the report says %d, the evidence gives %d", want, got))}
}

// undeclared looks for downtime in the readings that the report did not
// declare as an outage.
func undeclared(report *model.Report, out availability.Output) []check {
	declared := map[string][]model.Interval{}
	for _, o := range report.Outages {
		declared[o.ComponentID] = append(declared[o.ComponentID],
			model.Interval{From: o.From, To: o.To})
	}
	var missing int64
	for _, o := range out.Outages {
		remainder := availability.Subtract(
			[]model.Interval{{From: o.From, To: o.To}}, declared[o.ComponentID])
		missing += availability.Total(remainder)
	}
	if missing > 0 {
		return []check{fault("declared outages",
			fmt.Sprintf("the evidence shows %d seconds of downtime the report does not declare", missing))}
	}
	return []check{pass("declared outages",
		"every interval the evidence shows as down is declared in the report")}
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
