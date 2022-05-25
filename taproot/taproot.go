package taproot

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	TagTapLeafElements    = []byte("TapLeaf/elements")
	TagTapBranchElements  = []byte("TapBranch/elements")
	TagTapSighashElements = []byte("TapSighash/elements")
	TagTapTweakElements   = []byte("TapTweak/elements")
)

const (

	// BaseElementsLeafVersion defines the base leaf version for elements chains
	// Bitcoin is using 0xc0
	BaseElementsLeafVersion txscript.TapscriptLeafVersion = 0xc4
)

// TapElementsLeaf implements txscript.TapNode interface
type TapElementsLeaf struct {
	txscript.TapLeaf
}

// TapHash overwrites the txscript.TapLeaf.TapHash method using elements tag
func (t TapElementsLeaf) TapHash() chainhash.Hash {
	var leafEncoding bytes.Buffer
	_ = leafEncoding.WriteByte(byte(t.LeafVersion))
	_ = wire.WriteVarBytes(&leafEncoding, 0, t.Script)

	return *chainhash.TaggedHash(TagTapLeafElements, leafEncoding.Bytes())
}

// NewTapElementsLeaf overwrite the NewTapLeaf constructor
func NewTapElementsLeaf(leafVersion txscript.TapscriptLeafVersion, script []byte) txscript.TapNode {
	return &TapElementsLeaf{
		txscript.NewTapLeaf(leafVersion, script),
	}
}

// TapElementsBranch implements txscript.TapNode interface
type TapElementsBranch struct {
	txscript.TapBranch
}

func (t TapElementsBranch) TapHash() chainhash.Hash {
	leftHash := t.Left().TapHash()
	rightHash := t.Right().TapHash()
	return tapElementsBranchHash(leftHash[:], rightHash[:])
}

// NewTapElementsBranch creates a new branch from two nodes
func NewTapElementsBranch(l, r txscript.TapNode) TapElementsBranch {
	return TapElementsBranch{
		txscript.NewTapBranch(l, r),
	}
}

type TaprootPayment struct {
	InternalKey *btcec.PublicKey
}

// tapElementsBranchHash takes the raw tap hashes of the right and left nodes and
// hashes them into a branch. it uses the elements tag instead of bitcoin one
func tapElementsBranchHash(l, r []byte) chainhash.Hash {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}

	return *chainhash.TaggedHash(
		TagTapBranchElements, l[:], r[:],
	)
}

// TapscriptElementsProof overrides the TapscriptProof struct (with elements tapLeaf)
type TapscriptElementsProof struct {
	TapElementsLeaf
	RootNode       txscript.TapNode
	InclusionProof []byte
}

// ToControlBlock maps the tapscript proof into a fully valid control block
// that can be used as a witness item for a tapscript spend.
func (t *TapscriptElementsProof) ToControlBlock(internalKey *btcec.PublicKey) txscript.ControlBlock {
	// Compute the total level output commitment based on the populated
	// root node.
	rootHash := t.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, rootHash[:],
	)

	// With the commitment computed we can obtain the bit that denotes if
	// the resulting key has an odd y coordinate or not.
	var outputKeyYIsOdd bool
	if taprootKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
		outputKeyYIsOdd = true
	}

	return txscript.ControlBlock{
		InternalKey:     internalKey,
		OutputKeyYIsOdd: outputKeyYIsOdd,
		LeafVersion:     t.TapElementsLeaf.LeafVersion,
		InclusionProof:  t.InclusionProof,
	}
}

// IndexedTapScriptTree reprints a fully contracted tapscript tree. The
// RootNode can be used to traverse down the full tree. In addition, complete
// inclusion proofs for each leaf are included as well, with an index into the
// slice of proof based on the tap leaf hash of a given leaf.
type IndexedElementsTapScriptTree struct {
	RootNode         txscript.TapNode
	LeafMerkleProofs []TapscriptElementsProof
	LeafProofIndex   map[chainhash.Hash]int
}

// NewIndexedTapScriptTree creates a new empty tapscript tree that has enough
// space to hold information for the specified amount of leaves.
func NewIndexedElementsTapScriptTree(numLeaves int) *IndexedElementsTapScriptTree {
	return &IndexedElementsTapScriptTree{
		LeafMerkleProofs: make([]TapscriptElementsProof, numLeaves),
		LeafProofIndex:   make(map[chainhash.Hash]int, numLeaves),
	}
}

// AssembleTaprootScriptTree constructs a new fully indexed tapscript tree
// given a series of leaf nodes. A combination of a recursive data structure,
// and an array-based representation are used to both generate the tree and
// also accumulate all the necessary inclusion proofs in the same path. See the
// comment of blockchain.BuildMerkleTreeStore for further details.
func AssembleTaprootScriptTree(leaves ...TapElementsLeaf) *IndexedElementsTapScriptTree {
	// If there's only a single leaf, then that becomes our root.
	if len(leaves) == 1 {
		// A lone leaf has no additional inclusion proof, as a verifier
		// will just hash the leaf as the sole branch.
		leaf := leaves[0]
		return &IndexedElementsTapScriptTree{
			RootNode: leaf,
			LeafProofIndex: map[chainhash.Hash]int{
				leaf.TapHash(): 0,
			},
			LeafMerkleProofs: []TapscriptElementsProof{
				{
					TapElementsLeaf: leaf,
					RootNode:        leaf,
					InclusionProof:  nil,
				},
			},
		}
	}

	// We'll start out by populating the leaf index which maps a leave's
	// taphash to its index within the tree.
	scriptTree := NewIndexedElementsTapScriptTree(len(leaves))
	for i, leaf := range leaves {
		leafHash := leaf.TapHash()
		scriptTree.LeafProofIndex[leafHash] = i
	}

	var branches []TapElementsBranch
	for i := 0; i < len(leaves); i += 2 {
		// If there's only a single leaf left, then we'll merge this
		// with the last branch we have.
		if i == len(leaves)-1 {
			branchToMerge := branches[len(branches)-1]
			leaf := leaves[i]
			newBranch := NewTapElementsBranch(branchToMerge, leaf)

			branches[len(branches)-1] = newBranch

			// The leaf includes the existing branch within its
			// inclusion proof.
			branchHash := branchToMerge.TapHash()

			scriptTree.LeafMerkleProofs[i].TapElementsLeaf = leaf
			scriptTree.LeafMerkleProofs[i].InclusionProof = append(
				scriptTree.LeafMerkleProofs[i].InclusionProof,
				branchHash[:]...,
			)

			// We'll also add this right hash to the inclusion of
			// the left and right nodes of the branch.
			lastLeafHash := leaf.TapHash()

			leftLeafHash := branchToMerge.Left().TapHash()
			leftLeafIndex := scriptTree.LeafProofIndex[leftLeafHash]
			scriptTree.LeafMerkleProofs[leftLeafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leftLeafIndex].InclusionProof,
				lastLeafHash[:]...,
			)

			rightLeafHash := branchToMerge.Right().TapHash()
			rightLeafIndex := scriptTree.LeafProofIndex[rightLeafHash]
			scriptTree.LeafMerkleProofs[rightLeafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[rightLeafIndex].InclusionProof,
				lastLeafHash[:]...,
			)

			continue
		}

		// While we still have leaves left, we'll combine two of them
		// into a new branch node.
		left, right := leaves[i], leaves[i+1]
		nextBranch := NewTapElementsBranch(left, right)
		branches = append(branches, nextBranch)

		// The left node will use the right node as part of its
		// inclusion proof, and vice versa.
		leftHash := left.TapHash()
		rightHash := right.TapHash()

		scriptTree.LeafMerkleProofs[i].TapElementsLeaf = left
		scriptTree.LeafMerkleProofs[i].InclusionProof = append(
			scriptTree.LeafMerkleProofs[i].InclusionProof,
			rightHash[:]...,
		)

		scriptTree.LeafMerkleProofs[i+1].TapElementsLeaf = right
		scriptTree.LeafMerkleProofs[i+1].InclusionProof = append(
			scriptTree.LeafMerkleProofs[i+1].InclusionProof,
			leftHash[:]...,
		)
	}

	// In this second phase, we'll merge all the leaf branches we have one
	// by one until we have our final root.
	var rootNode txscript.TapNode
	for len(branches) != 0 {
		// When we only have a single branch left, then that becomes
		// our root.
		if len(branches) == 1 {
			rootNode = branches[0]
			break
		}

		left, right := branches[0], branches[1]

		newBranch := NewTapElementsBranch(left, right)

		branches = branches[2:]

		branches = append(branches, newBranch)

		// Accumulate the sibling hash of this new branch for all the
		// leaves that are its children.
		leftLeafDescendants := leafDescendants(left)
		rightLeafDescendants := leafDescendants(right)

		leftHash, rightHash := left.TapHash(), right.TapHash()

		// For each left hash that's a leaf descendants, well add the
		// right sibling as that sibling is needed to construct the new
		// internal branch we just created. We also do the same for the
		// siblings of the right node.
		for _, leftLeaf := range leftLeafDescendants {
			leafHash := leftLeaf.TapHash()
			leafIndex := scriptTree.LeafProofIndex[leafHash]

			scriptTree.LeafMerkleProofs[leafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leafIndex].InclusionProof,
				rightHash[:]...,
			)
		}
		for _, rightLeaf := range rightLeafDescendants {
			leafHash := rightLeaf.TapHash()
			leafIndex := scriptTree.LeafProofIndex[leafHash]

			scriptTree.LeafMerkleProofs[leafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leafIndex].InclusionProof,
				leftHash[:]...,
			)
		}
	}

	// Populate the top level root node pointer, as well as the pointer in
	// each proof.
	scriptTree.RootNode = rootNode
	for i := range scriptTree.LeafMerkleProofs {
		scriptTree.LeafMerkleProofs[i].RootNode = rootNode
	}

	return scriptTree
}

func leafDescendants(node txscript.TapNode) []txscript.TapNode {
	// A leaf node has no decedents, so we just return it directly.
	if node.Left() == nil && node.Right() == nil {
		return []txscript.TapNode{node}
	}

	// Otherwise, get the descendants of the left and right sub-trees to
	// return.
	leftLeaves := leafDescendants(node.Left())
	rightLeaves := leafDescendants(node.Right())

	return append(leftLeaves, rightLeaves...)
}
