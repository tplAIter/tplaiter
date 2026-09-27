package bootstrap

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

type MerkleHash [sha256.Size]byte

func HashLeaf(b []byte) MerkleHash { return sha256.Sum256(append([]byte{0}, b...)) }
func HashChildren(a, b MerkleHash) MerkleHash {
	v := make([]byte, 65)
	v[0] = 1
	copy(v[1:], a[:])
	copy(v[33:], b[:])
	return sha256.Sum256(v)
}
func EmptyTreeHash() MerkleHash { return sha256.Sum256(nil) }
func VerifyInclusion(leaf []byte, index, size uint64, root MerkleHash, proof []MerkleHash) error {
	if size == 0 || index >= size {
		return fmt.Errorf("bootstrap: invalid inclusion proof bounds")
	}
	fn, sn := index, size-1
	got := HashLeaf(leaf)
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("bootstrap: inclusion proof trailing hashes")
		}
		if fn&1 == 1 || fn == sn {
			got = HashChildren(p, got)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			got = HashChildren(got, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || subtle.ConstantTimeCompare(got[:], root[:]) != 1 {
		return fmt.Errorf("bootstrap: invalid transparency inclusion proof")
	}
	return nil
}
func VerifyConsistency(old, new uint64, oldRoot, newRoot MerkleHash, proof []MerkleHash) error {
	if old == 0 || old > new {
		return fmt.Errorf("bootstrap: invalid consistency proof bounds")
	}
	if old == new {
		if len(proof) > 0 || subtle.ConstantTimeCompare(oldRoot[:], newRoot[:]) != 1 {
			return fmt.Errorf("bootstrap: inconsistent equal-size checkpoint")
		}
		return nil
	}
	fn, sn := old-1, new-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var first, second MerkleHash
	offset := 0
	if fn == 0 {
		first, second = oldRoot, oldRoot
	} else {
		if len(proof) == 0 {
			return fmt.Errorf("bootstrap: empty consistency proof")
		}
		first, second, offset = proof[0], proof[0], 1
	}
	for _, sibling := range proof[offset:] {
		if sn == 0 {
			return fmt.Errorf("bootstrap: consistency proof trailing hashes")
		}
		if fn&1 == 1 || fn == sn {
			first = HashChildren(sibling, first)
			second = HashChildren(sibling, second)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			second = HashChildren(second, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || subtle.ConstantTimeCompare(first[:], oldRoot[:]) != 1 || subtle.ConstantTimeCompare(second[:], newRoot[:]) != 1 {
		return fmt.Errorf("bootstrap: invalid transparency consistency proof")
	}
	return nil
}
func merkleHash(v string) (MerkleHash, error) {
	b, e := rawDigest(v)
	if e != nil {
		return MerkleHash{}, e
	}
	var h MerkleHash
	copy(h[:], b)
	return h, nil
}
