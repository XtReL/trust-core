package tlog

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = LeafHash([]byte(fmt.Sprintf("entry-%d", i)))
	}
	return out
}

func TestEmptyAndSingle(t *testing.T) {
	empty := EmptyRoot()
	if hex.EncodeToString(empty[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("wrong empty root")
	}
	// RFC 6962 leaf hash of the empty string.
	l := LeafHash(nil)
	if hex.EncodeToString(l[:]) != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatal("wrong leaf hash")
	}
}

func TestInclusionAllSizes(t *testing.T) {
	for n := 1; n <= 70; n++ {
		ls := leaves(n)
		root := RootFromLeaves(ls)
		for i := 0; i < n; i++ {
			p, err := InclusionProof(ls, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(ls[i], uint64(i), uint64(n), p, root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if n > 1 {
				if VerifyInclusion(ls[(i+1)%n], uint64(i), uint64(n), p, root) == nil {
					t.Fatalf("n=%d i=%d: wrong leaf accepted", n, i)
				}
				bad := append([]Hash(nil), p...)
				bad[0][0] ^= 1
				if VerifyInclusion(ls[i], uint64(i), uint64(n), bad, root) == nil {
					t.Fatalf("n=%d i=%d: tampered proof accepted", n, i)
				}
			}
		}
		if VerifyInclusion(ls[0], uint64(n), uint64(n), nil, root) == nil {
			t.Fatal("out-of-range index accepted")
		}
	}
}
