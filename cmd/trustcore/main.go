// Command trustcore records signed events into a transparency log and
// verifies logs, entries and checkpoints.
//
// Exit codes: 0 = ok, 1 = verification failed, 2 = usage or I/O error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	trustcore "github.com/XtReL/trust-core"
	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/rotate"
	"github.com/XtReL/trust-core/tlog"
	"github.com/XtReL/trust-core/tlog/filelog"
	"github.com/XtReL/trust-core/verify"
)

const usage = `trustcore — verifiable evidence log

Commands:
  keygen        -out PREFIX [-name ORIGIN]
  init          -log DIR -origin ORIGIN -log-key KEY
  record        -log DIR -origin ORIGIN -log-key KEY -key ATTESTER_KEY -event FILE
  verify        -log DIR -log-pub PUB -attester-pub PUB[,PUB] [-origin ORIGIN] [-previous CHECKPOINT]
  prove         -log DIR -index N
  verify-entry  -entry FILE -proof FILE -log-pub PUB [-attester-pub PUB] [-origin ORIGIN]
  rotate        -from DIR -from-origin ORIGIN -from-pub OLD.pub [-from-key OLD.key]
                [-trusted-checkpoint FILE] -new-key NEW.key -to DIR [-note TEXT]
  verify-chain  -manifest FILE [-json]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "record":
		err = cmdRecord(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "prove":
		err = cmdProve(os.Args[2:])
	case "verify-entry":
		err = cmdVerifyEntry(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "verify-chain":
		err = cmdVerifyChain(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: "+format+"\n", a...)
	os.Exit(1)
}

func need(fs *flag.FlagSet, names ...string) error {
	for _, n := range names {
		if fs.Lookup(n).Value.String() == "" {
			return fmt.Errorf("%s: -%s is required", fs.Name(), n)
		}
	}
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "path prefix: writes PREFIX.key (private) and PREFIX.pub")
	name := fs.String("name", "", "log origin, to print the note verifier key for witnesses")
	fs.Parse(args)
	if err := need(fs, "out"); err != nil {
		return err
	}
	pub, priv, err := keys.Generate()
	if err != nil {
		return err
	}
	if err := keys.WritePrivate(*out+".key", priv); err != nil {
		return err
	}
	if err := keys.WritePublic(*out+".pub", pub); err != nil {
		return err
	}
	fmt.Printf("key id:   %s\nprivate:  %s.key  (never commit this)\npublic:   %s.pub\n", keys.KeyID(pub), *out, *out)
	if *name != "" {
		fmt.Printf("vkey:     %s\n", tlog.VerifierKey(*name, pub))
	}
	return nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("log", "", "log directory")
	origin := fs.String("origin", "", "log identity, e.g. trust.example.com/xtrel/gatekeeper")
	logKey := fs.String("log-key", "", "log operator private key")
	fs.Parse(args)
	if err := need(fs, "log", "origin", "log-key"); err != nil {
		return err
	}
	s, err := keys.LoadSigner(*logKey)
	if err != nil {
		return err
	}
	if _, err := filelog.Init(*dir, *origin, s); err != nil {
		return err
	}
	fmt.Printf("initialised empty log %s at %s\n", *origin, *dir)
	return nil
}

func cmdRecord(args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	dir := fs.String("log", "", "log directory")
	origin := fs.String("origin", "", "log identity")
	logKey := fs.String("log-key", "", "log operator private key")
	key := fs.String("key", "", "attester private key")
	evPath := fs.String("event", "", "event JSON file")
	fs.Parse(args)
	if err := need(fs, "log", "origin", "log-key", "key", "event"); err != nil {
		return err
	}
	logSigner, err := keys.LoadSigner(*logKey)
	if err != nil {
		return err
	}
	attester, err := keys.LoadSigner(*key)
	if err != nil {
		return err
	}
	l, err := filelog.Open(*dir, *origin, logSigner)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*evPath)
	if err != nil {
		return err
	}
	var ev event.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("event file: %w", err)
	}
	rec := trustcore.Recorder{Attester: attester, Log: l}
	receipt, err := rec.Record(ev)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(receipt)
}

func loadVerifiers(list string) ([]attest.Verifier, error) {
	var out []attest.Verifier
	for _, p := range splitComma(list) {
		pub, err := keys.LoadPublic(p)
		if err != nil {
			return nil, err
		}
		out = append(out, keys.NewVerifier(pub))
	}
	return out, nil
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("log", "", "log directory")
	logPub := fs.String("log-pub", "", "log operator public key")
	attPub := fs.String("attester-pub", "", "trusted attester public key(s), comma-separated")
	origin := fs.String("origin", "", "expected log origin (recommended)")
	previous := fs.String("previous", "", "an earlier signed checkpoint file you kept")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	fs.Parse(args)
	if err := need(fs, "log", "log-pub", "attester-pub"); err != nil {
		return err
	}
	lk, err := keys.LoadPublic(*logPub)
	if err != nil {
		return err
	}
	atts, err := loadVerifiers(*attPub)
	if err != nil {
		return err
	}
	opts := verify.Options{Dir: *dir, Origin: *origin, LogKey: lk, Attesters: atts}
	if *previous != "" {
		if opts.Previous, err = os.ReadFile(*previous); err != nil {
			return err
		}
	}
	rep, err := verify.Log(opts)
	if err != nil {
		fail("%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		fmt.Printf("log:       %s\nsize:      %d\nroot:      %s\n", rep.Origin, rep.Size, rep.Root)
		if rep.PreviousSize != nil {
			fmt.Printf("history:   first %d entries match the previous checkpoint\n", *rep.PreviousSize)
		}
		if rep.Uncommitted > 0 {
			fmt.Printf("warning:   %d entry file(s) not covered by the checkpoint\n", rep.Uncommitted)
		}
	}
	if !rep.OK {
		for _, p := range rep.Problems {
			fmt.Fprintln(os.Stderr, " -", p)
		}
		fail("%d problem(s)", len(rep.Problems))
	}
	fmt.Println("OK: checkpoint signature, Merkle root and all entry signatures verified")
	return nil
}

func cmdProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	dir := fs.String("log", "", "log directory")
	index := fs.Uint64("index", 0, "entry index")
	fs.Parse(args)
	if err := need(fs, "log"); err != nil {
		return err
	}
	p, err := verify.Prove(*dir, *index)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

func cmdVerifyEntry(args []string) error {
	fs := flag.NewFlagSet("verify-entry", flag.ExitOnError)
	entryPath := fs.String("entry", "", "entry file (DSSE envelope)")
	proofPath := fs.String("proof", "", "proof JSON from 'trustcore prove'")
	logPub := fs.String("log-pub", "", "log operator public key")
	attPub := fs.String("attester-pub", "", "trusted attester public key(s), optional")
	origin := fs.String("origin", "", "expected log origin (recommended)")
	fs.Parse(args)
	if err := need(fs, "entry", "proof", "log-pub"); err != nil {
		return err
	}
	entry, err := os.ReadFile(*entryPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*proofPath)
	if err != nil {
		return err
	}
	var p verify.Proof
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	lk, err := keys.LoadPublic(*logPub)
	if err != nil {
		return err
	}
	atts, err := loadVerifiers(*attPub)
	if err != nil {
		return err
	}
	if err := verify.Entry(entry, p, *origin, lk, atts); err != nil {
		fail("%v", err)
	}
	fmt.Printf("OK: entry %d is included in the log at size %d\n", p.Index, p.Size)
	return nil
}

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	from := fs.String("from", "", "log directory of the epoch being rotated")
	fromOrigin := fs.String("from-origin", "", "origin of the epoch being rotated")
	fromPub := fs.String("from-pub", "", "public key of the epoch being rotated")
	fromKey := fs.String("from-key", "", "private key of the epoch being rotated: planned rotation")
	trusted := fs.String("trusted-checkpoint", "", "checkpoint kept outside the log: required without -from-key (unplanned rotation)")
	newKey := fs.String("new-key", "", "private key of the new epoch")
	to := fs.String("to", "", "log directory of the new epoch")
	note := fs.String("note", "", "free text recorded in the genesis")
	fs.Parse(args)
	if err := need(fs, "from", "from-origin", "from-pub", "new-key", "to"); err != nil {
		return err
	}
	oldPub, err := keys.LoadPublic(*fromPub)
	if err != nil {
		return err
	}
	newSigner, err := keys.LoadSigner(*newKey)
	if err != nil {
		return err
	}
	var res rotate.Result
	if *fromKey != "" {
		if *trusted != "" {
			return fmt.Errorf("rotate: -trusted-checkpoint is for unplanned rotations; a planned rotation freezes the current checkpoint")
		}
		oldSigner, err := keys.LoadSigner(*fromKey)
		if err != nil {
			return err
		}
		if !oldSigner.Public().Equal(oldPub) {
			return fmt.Errorf("rotate: -from-key does not match -from-pub")
		}
		res, err = rotate.Planned(*from, *fromOrigin, oldSigner, *to, newSigner, *note)
		if err != nil {
			return err
		}
	} else {
		if *trusted == "" {
			return fmt.Errorf("rotate: without -from-key (unplanned rotation) -trusted-checkpoint is required")
		}
		cp, err := os.ReadFile(*trusted)
		if err != nil {
			return err
		}
		res, err = rotate.Unplanned(*from, *fromOrigin, oldPub, cp, *to, newSigner, *note)
		if err != nil {
			return err
		}
	}
	kind := "planned"
	if *fromKey == "" {
		kind = "unplanned"
	}
	fmt.Printf("rotation: %s\nepoch:    %d\norigin:   %s\nkey id:   %s\nvkey:     %s\nfrozen:   %s at size %d\n",
		kind, res.Epoch, res.Origin, res.NewKeyID, res.VerifierKey, *fromOrigin, res.FrozenSize)
	if res.AfterFreeze > 0 {
		fmt.Printf("ignored:  %d old-epoch entry file(s) after the freeze point\n", res.AfterFreeze)
	}
	if kind == "unplanned" {
		fmt.Println("verifiers must confirm this key id with you out of band and set acceptUnplanned")
	}
	return nil
}

func cmdVerifyChain(args []string) error {
	fs := flag.NewFlagSet("verify-chain", flag.ExitOnError)
	manifest := fs.String("manifest", "", "your manifest of trusted epochs and keys (JSON)")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	fs.Parse(args)
	if err := need(fs, "manifest"); err != nil {
		return err
	}
	m, err := verify.LoadManifest(*manifest)
	if err != nil {
		return err
	}
	rep, err := verify.Chain(m)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		for _, e := range rep.Epochs {
			status := "ok"
			if !e.OK {
				status = "FAILED"
			}
			fmt.Printf("epoch %d:  %s  size %d  root %s", e.Epoch, e.Origin, e.Size, e.Root)
			if e.Rotation != "" {
				fmt.Printf("  (%s rotation)", e.Rotation)
			}
			if e.Frozen {
				fmt.Print("  frozen")
			}
			fmt.Printf("  %s\n", status)
			if e.Unconfirmed > 0 {
				fmt.Printf("  warning: %d entry(ies) after the freeze point are NOT confirmed: %v\n", e.Unconfirmed, e.UnconfirmedEntries)
			}
		}
	}
	if !rep.OK {
		for _, p := range rep.Problems {
			fmt.Fprintln(os.Stderr, " -", p)
		}
		fail("%d problem(s)", len(rep.Problems))
	}
	fmt.Println("OK: every epoch verified and linked by its genesis")
	return nil
}
