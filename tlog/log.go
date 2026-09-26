package tlog

// Log is an append-only transparency log. Backends: filelog (local POSIX
// directory, for the first slice) and, later, Tessera. Callers depend only
// on this interface so that swapping backends does not touch verticals.
type Log interface {
	// Append adds one entry and returns its index. After Append returns,
	// SignedCheckpoint commits to the new entry.
	Append(entry []byte) (uint64, error)
	// Size returns the number of committed entries.
	Size() (uint64, error)
	// Entry returns the exact bytes of a committed entry.
	Entry(index uint64) ([]byte, error)
	// SignedCheckpoint returns the latest signed checkpoint note.
	SignedCheckpoint() ([]byte, error)
}
