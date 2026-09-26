// Package filelog is the first log backend: a plain directory that can be
// committed to git, attached to a CI run or handed to an auditor.
//
//	<dir>/checkpoint                 signed C2SP checkpoint (note)
//	<dir>/entries/00000000000000000000.json   entry 0 (DSSE envelope bytes)
//	<dir>/entries/00000000000000000001.json   entry 1 ...
//
// It is single-writer (guarded by a lock file) and recomputes the root in
// O(n) on every append: fine for one repository's history, not for a
// hosted multi-tenant service. That is what the Tessera backend is for.
package filelog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/XtReL/trust-core/tlog"
)

const (
	checkpointFile = "checkpoint"
	entriesDir     = "entries"
	lockFile       = ".lock"
)

// EntryPath returns the path of entry index inside dir.
func EntryPath(dir string, index uint64) string {
	return filepath.Join(dir, entriesDir, fmt.Sprintf("%020d.json", index))
}

// CheckpointPath returns the path of the signed checkpoint inside dir.
func CheckpointPath(dir string) string { return filepath.Join(dir, checkpointFile) }

// Log is a writable file-based log.
type Log struct {
	dir    string
	origin string
	signer tlog.NoteSigner
}

var _ tlog.Log = (*Log)(nil)

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Init creates an empty log in dir with a signed size-0 checkpoint.
// origin names the log, e.g. "trust.example.com/xtrel/gatekeeper".
func Init(dir, origin string, signer tlog.NoteSigner) (*Log, error) {
	if _, err := os.Stat(CheckpointPath(dir)); err == nil {
		return nil, fmt.Errorf("filelog: %s already contains a log", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, entriesDir), 0o755); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, origin: origin, signer: signer}
	if err := l.writeCheckpoint(tlog.Checkpoint{Origin: origin, Size: 0, Root: tlog.EmptyRoot()}); err != nil {
		return nil, err
	}
	return l, nil
}

// Open opens an existing log for writing. The current checkpoint must
// verify under the signer's own key, so a tampered or foreign log directory
// is refused instead of being silently extended.
func Open(dir, origin string, signer tlog.NoteSigner) (*Log, error) {
	msg, err := os.ReadFile(CheckpointPath(dir))
	if err != nil {
		return nil, err
	}
	if _, err := tlog.OpenCheckpoint(msg, origin, signer.Public()); err != nil {
		return nil, fmt.Errorf("filelog: current checkpoint does not verify under this log key: %w", err)
	}
	return &Log{dir: dir, origin: origin, signer: signer}, nil
}

func (l *Log) writeCheckpoint(c tlog.Checkpoint) error {
	signed, err := tlog.SignCheckpoint(c, l.signer)
	if err != nil {
		return err
	}
	return writeAtomic(CheckpointPath(l.dir), signed, 0o644)
}

func (l *Log) current() (tlog.Checkpoint, error) {
	msg, err := os.ReadFile(CheckpointPath(l.dir))
	if err != nil {
		return tlog.Checkpoint{}, err
	}
	return tlog.OpenCheckpoint(msg, l.origin, l.signer.Public())
}

// Append writes the entry, then publishes a new signed checkpoint. If the
// process dies in between, the entry stays uncommitted (not covered by any
// checkpoint) and the next Append refuses to proceed until it is resolved.
func (l *Log) Append(entry []byte) (uint64, error) {
	lock := filepath.Join(l.dir, lockFile)
	f, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("filelog: log is locked by another writer (%s): %w", lock, err)
	}
	f.Close()
	defer os.Remove(lock)

	cp, err := l.current()
	if err != nil {
		return 0, err
	}
	index := cp.Size
	path := EntryPath(l.dir, index)
	if _, err := os.Stat(path); err == nil {
		return 0, fmt.Errorf("filelog: uncommitted entry %s exists; inspect it before appending", path)
	}
	if err := writeAtomic(path, entry, 0o644); err != nil {
		return 0, err
	}
	leaves, err := LeafHashes(l.dir, index+1)
	if err != nil {
		return 0, err
	}
	next := tlog.Checkpoint{Origin: l.origin, Size: index + 1, Root: tlog.RootFromLeaves(leaves)}
	if err := l.writeCheckpoint(next); err != nil {
		return 0, err
	}
	return index, nil
}

// Size returns the committed size.
func (l *Log) Size() (uint64, error) {
	cp, err := l.current()
	return cp.Size, err
}

// Entry returns a committed entry.
func (l *Log) Entry(index uint64) ([]byte, error) {
	size, err := l.Size()
	if err != nil {
		return nil, err
	}
	if index >= size {
		return nil, fmt.Errorf("filelog: entry %d is not committed (size %d)", index, size)
	}
	return os.ReadFile(EntryPath(l.dir, index))
}

// SignedCheckpoint returns the latest signed checkpoint.
func (l *Log) SignedCheckpoint() ([]byte, error) { return os.ReadFile(CheckpointPath(l.dir)) }

// LeafHashes reads entries [0, n) and returns their leaf hashes.
func LeafHashes(dir string, n uint64) ([]tlog.Hash, error) {
	leaves := make([]tlog.Hash, 0, n)
	for i := uint64(0); i < n; i++ {
		data, err := os.ReadFile(EntryPath(dir, i))
		if err != nil {
			return nil, fmt.Errorf("filelog: reading entry %d: %w", i, err)
		}
		leaves = append(leaves, tlog.LeafHash(data))
	}
	return leaves, nil
}

// CountEntryFiles counts consecutive entry files starting at index 0.
func CountEntryFiles(dir string) (uint64, error) {
	var n uint64
	for {
		_, err := os.Stat(EntryPath(dir, n))
		if errors.Is(err, os.ErrNotExist) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n++
	}
}
