// Package tlog implements the transparency-log primitives Trust Core needs:
// RFC 6962/9162 Merkle hashing and inclusion proofs, and C2SP checkpoints
// signed as notes. These are the same formats used by Certificate
// Transparency, the Go checksum database, Sigstore and Tessera, so logs can
// later be moved to Tessera and co-signed by public witnesses.
package tlog

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Hash is a SHA-256 Merkle tree hash.
type Hash [sha256.Size]byte

// LeafHash is SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRoot is the root of an empty tree: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// split returns the largest power of two strictly less than n (n >= 2).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return NodeHash(mth(leaves[:k]), mth(leaves[k:]))
}

// RootFromLeaves computes the Merkle tree hash over leaf hashes.
// It is O(n); large logs should use a tiled backend such as Tessera.
func RootFromLeaves(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	return mth(leaves)
}

func path(m int, leaves []Hash) []Hash {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), mth(leaves[:k]))
}

// InclusionProof returns the audit path for leaf index in the tree formed
// by leaves.
func InclusionProof(leaves []Hash, index uint64) ([]Hash, error) {
	if index >= uint64(len(leaves)) {
		return nil, fmt.Errorf("tlog: index %d out of range for size %d", index, len(leaves))
	}
	return path(int(index), leaves), nil
}

// ErrInvalidProof is returned when an inclusion proof does not verify.
var ErrInvalidProof = errors.New("tlog: invalid inclusion proof")

// VerifyInclusion checks that leaf is at index in a tree of size with the
// given root, following RFC 9162 section 2.1.3.2.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	if index >= size {
		return ErrInvalidProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrInvalidProof
	}
	return nil
}
