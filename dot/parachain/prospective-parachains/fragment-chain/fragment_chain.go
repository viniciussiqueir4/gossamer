package fragmentchain

import (
	"bytes"
	"fmt"
	"iter"
	"slices"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	inclusionemulator "github.com/ChainSafe/gossamer/dot/parachain/util/inclusion-emulator"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/tidwall/btree"
)

type CandidateState int

const (
	Seconded CandidateState = iota
	Backed
)

func forkSelectionRule(hash1, hash2 parachaintypes.CandidateHash) int {
	return bytes.Compare(hash1.Value[:], hash2.Value[:])
}

// CandidateEntry represents a candidate into the CandidateStorage
// TODO: Should CandidateEntry implements `HypotheticalOrConcreteCandidate`
type CandidateEntry struct {
	candidateHash      parachaintypes.CandidateHash
	parentHeadDataHash common.Hash
	outputHeadDataHash common.Hash
	relayParent        common.Hash
	// TODO: this is under a Arc<ProspectiveCandidate> smart pointer, should we
	// have that here? maybe some specialized struct that protects the underlying data?
	candidate inclusionemulator.ProspectiveCandidate
	state     CandidateState
}

func (c *CandidateEntry) Hash() parachaintypes.CandidateHash {
	return c.candidateHash
}

func NewCandidateEntry(
	candidateHash parachaintypes.CandidateHash,
	candidate parachaintypes.CommittedCandidateReceipt,
	persistedValidationData parachaintypes.PersistedValidationData,
	state CandidateState,
) (*CandidateEntry, error) {
	pvdHash, err := persistedValidationData.Hash()
	if err != nil {
		return nil, fmt.Errorf("while hashing persisted validation data: %w", err)
	}

	if pvdHash != candidate.Descriptor.PersistedValidationDataHash {
		return nil, ErrPersistedValidationDataMismatch
	}

	parendHeadDataHash, err := persistedValidationData.ParentHead.Hash()
	if err != nil {
		return nil, fmt.Errorf("while hashing parent head data: %w", err)
	}

	outputHeadDataHash, err := candidate.Commitments.HeadData.Hash()
	if err != nil {
		return nil, fmt.Errorf("while hashing output head data: %w", err)
	}

	if parendHeadDataHash == outputHeadDataHash {
		return nil, ErrCandidateEntryZeroLengthCycle
	}

	return &CandidateEntry{
		candidateHash:      candidateHash,
		parentHeadDataHash: parendHeadDataHash,
		outputHeadDataHash: outputHeadDataHash,
		relayParent:        candidate.Descriptor.RelayParent,
		state:              state,
		candidate: inclusionemulator.ProspectiveCandidate{
			Commitments:             candidate.Commitments,
			PersistedValidationData: persistedValidationData,
			PoVHash:                 candidate.Descriptor.PovHash,
			ValidationCodeHash:      candidate.Descriptor.ValidationCodeHash,
		},
	}, nil
}

// CandidateStorage is an utility for storing candidates and information about them such as
// their relay-parents and their backing states. This does not assume any restriction on whether
// or not candidates form a chain. Useful for storing all kinds of candidates.
type CandidateStorage struct {
	byParentHead    map[common.Hash]map[parachaintypes.CandidateHash]any
	byOutputHead    map[common.Hash]map[parachaintypes.CandidateHash]any
	byCandidateHash map[parachaintypes.CandidateHash]*CandidateEntry
}

func NewCandidateStorage() *CandidateStorage {
	return &CandidateStorage{
		byParentHead:    make(map[common.Hash]map[parachaintypes.CandidateHash]any),
		byOutputHead:    make(map[common.Hash]map[parachaintypes.CandidateHash]any),
		byCandidateHash: make(map[parachaintypes.CandidateHash]*CandidateEntry),
	}
}

func (c *CandidateStorage) AddPendingAvailabilityCandidate(
	candidateHash parachaintypes.CandidateHash,
	candidate parachaintypes.CommittedCandidateReceipt,
	persistedValidationData parachaintypes.PersistedValidationData,
) error {
	entry, err := NewCandidateEntry(candidateHash, candidate, persistedValidationData, Backed)
	if err != nil {
		return err
	}

	return c.addCandidateEntry(entry)
}

// Len return the number of stored candidate
func (c *CandidateStorage) Len() uint {
	return uint(len(c.byCandidateHash))
}

func (c *CandidateStorage) addCandidateEntry(candidate *CandidateEntry) error {
	_, ok := c.byCandidateHash[candidate.candidateHash]
	if ok {
		return ErrCandidateAlradyKnown
	}

	// updates the reference parent hash -> candidate
	// we don't check the `ok` value since the key can
	// exists in the map but pointing to a nil hashset
	setOfCandidates := c.byParentHead[candidate.parentHeadDataHash]
	if setOfCandidates == nil {
		setOfCandidates = make(map[parachaintypes.CandidateHash]any)
	}
	setOfCandidates[candidate.candidateHash] = struct{}{}
	c.byParentHead[candidate.parentHeadDataHash] = setOfCandidates

	// udpates the reference output hash -> candidate
	setOfCandidates = c.byOutputHead[candidate.outputHeadDataHash]
	if setOfCandidates == nil {
		setOfCandidates = make(map[parachaintypes.CandidateHash]any)
	}
	setOfCandidates[candidate.candidateHash] = struct{}{}
	c.byOutputHead[candidate.outputHeadDataHash] = setOfCandidates

	return nil
}

func (c *CandidateStorage) removeCandidate(candidateHash parachaintypes.CandidateHash) {
	entry, ok := c.byCandidateHash[candidateHash]
	if !ok {
		return
	}

	delete(c.byCandidateHash, candidateHash)

	if setOfCandidates, ok := c.byParentHead[entry.parentHeadDataHash]; ok {
		delete(setOfCandidates, candidateHash)
		if len(setOfCandidates) == 0 {
			delete(c.byParentHead, entry.parentHeadDataHash)
		}
	}

	if setOfCandidates, ok := c.byOutputHead[entry.outputHeadDataHash]; ok {
		delete(setOfCandidates, candidateHash)
		if len(setOfCandidates) == 0 {
			delete(c.byOutputHead, entry.outputHeadDataHash)
		}
	}
}

func (c *CandidateStorage) markBacked(candidateHash parachaintypes.CandidateHash) {
	entry, ok := c.byCandidateHash[candidateHash]
	if !ok {
		fmt.Println("candidate not found while marking as backed")
	}

	entry.state = Backed
	fmt.Println("candidate marked as backed")
}

func (c *CandidateStorage) contains(candidateHash parachaintypes.CandidateHash) bool {
	_, ok := c.byCandidateHash[candidateHash]
	return ok
}

// candidates returns an iterator over references to the stored candidates, in arbitrary order.
func (c *CandidateStorage) candidates() iter.Seq[*CandidateEntry] {
	return func(yield func(*CandidateEntry) bool) {
		for _, entry := range c.byCandidateHash {
			if !yield(entry) {
				return
			}
		}
	}
}

func (c *CandidateStorage) headDataByHash(hash common.Hash) *parachaintypes.HeadData {
	// first, search for candidates outputting this head data and extract the head data
	// from their commitments if they exist.
	// otherwise, search for candidates building upon this head data and extract the
	// head data from their persisted validation data if they exist.

	if setOfCandidateHashes, ok := c.byOutputHead[hash]; ok {
		for candidateHash := range setOfCandidateHashes {
			if candidate, ok := c.byCandidateHash[candidateHash]; ok {
				return &candidate.candidate.Commitments.HeadData
			}
		}
	}

	if setOfCandidateHashes, ok := c.byParentHead[hash]; ok {
		for candidateHash := range setOfCandidateHashes {
			if candidate, ok := c.byCandidateHash[candidateHash]; ok {
				return &candidate.candidate.PersistedValidationData.ParentHead
			}
		}
	}

	return nil
}

func (c *CandidateStorage) possibleBackedParaChildren(parentHeadHash common.Hash) iter.Seq[*CandidateEntry] {
	return func(yield func(*CandidateEntry) bool) {
		seqOfCandidateHashes, ok := c.byParentHead[parentHeadHash]
		if !ok {
			return
		}

		for candidateHash := range seqOfCandidateHashes {
			if entry, ok := c.byCandidateHash[candidateHash]; ok && entry.state == Backed {
				if !yield(entry) {
					return
				}
			}
		}
	}
}

// PendindAvailability is a candidate on-chain but pending availability, for special
// treatment in the `Scope`
type PendindAvailability struct {
	CandidateHash parachaintypes.CandidateHash
	RelayParent   inclusionemulator.RelayChainBlockInfo
}

// The scope of a fragment chain
type Scope struct {
	// the relay parent we're currently building on top of
	relayParent inclusionemulator.RelayChainBlockInfo
	// the other relay parents candidates are allowed to build upon,
	// mapped by the block number
	ancestors *btree.Map[uint, inclusionemulator.RelayChainBlockInfo]
	// the other relay parents candidates are allowed to build upon,
	// mapped by hash
	ancestorsByHash map[common.Hash]inclusionemulator.RelayChainBlockInfo
	// candidates pending availability at this block
	pendindAvailability []*PendindAvailability
	// the base constraints derived from the latest included candidate
	baseConstraints *inclusionemulator.Constraints
	// equal to `max_candidate_depth`
	maxDepth uint
}

// NewScopeWithAncestors defines a new scope, all arguments are straightforward
// expect ancestors. Ancestor should be in reverse order, starting with the parent
// of the relayParent, and proceeding backwards in block number decrements of 1.
// Ancestors not following these conditions will be rejected.
//
// This function will only consume ancestors up to the `MinRelayParentNumber` of the
// `baseConstraints`.
//
// Only ancestor whose children have the same session id as the relay parent's children
// should be provided. It is allowed to provide 0 ancestors.
func NewScopeWithAncestors(
	relayParent inclusionemulator.RelayChainBlockInfo,
	baseConstraints *inclusionemulator.Constraints,
	pendingAvailability []*PendindAvailability,
	maxDepth uint,
	ancestors iter.Seq[inclusionemulator.RelayChainBlockInfo],
) (*Scope, error) {
	ancestorsMap := btree.NewMap[uint, inclusionemulator.RelayChainBlockInfo](100)
	ancestorsByHash := make(map[common.Hash]inclusionemulator.RelayChainBlockInfo)

	prev := relayParent.Number
	for ancestor := range ancestors {
		if prev == 0 {
			return nil, ErrUnexpectedAncestor{Number: ancestor.Number, Prev: prev}
		}

		if ancestor.Number != prev-1 {
			return nil, ErrUnexpectedAncestor{Number: ancestor.Number, Prev: prev}
		}

		if prev == baseConstraints.MinRelayParentNumber {
			break
		}

		prev = ancestor.Number
		ancestorsByHash[ancestor.Hash] = ancestor
		ancestorsMap.Set(ancestor.Number, ancestor)
	}

	return &Scope{
		relayParent:         relayParent,
		baseConstraints:     baseConstraints,
		pendindAvailability: pendingAvailability,
		maxDepth:            maxDepth,
		ancestors:           ancestorsMap,
		ancestorsByHash:     ancestorsByHash,
	}, nil
}

// EarliestRelayParent gets the earliest relay-parent allowed in the scope of the fragment chain.
func (s *Scope) EarliestRelayParent() inclusionemulator.RelayChainBlockInfo {
	if iter := s.ancestors.Iter(); iter.Next() {
		return iter.Value()
	}
	return s.relayParent
}

// Ancestor gets the relay ancestor of the fragment chain by hash.
func (s *Scope) Ancestor(hash common.Hash) *inclusionemulator.RelayChainBlockInfo {
	if hash == s.relayParent.Hash {
		return &s.relayParent
	}

	if blockInfo, ok := s.ancestorsByHash[hash]; ok {
		return &blockInfo
	}

	return nil
}

// Whether the candidate in question is one pending availability in this scope.
func (s *Scope) GetPendingAvailability(candidateHash parachaintypes.CandidateHash) *PendindAvailability {
	for _, c := range s.pendindAvailability {
		if c.CandidateHash == candidateHash {
			return c
		}
	}
	return nil
}

// Fragment node is a node that belongs to a `BackedChain`. It holds constraints based on
// the ancestors in the chain
type FragmentNode struct {
	fragment                *inclusionemulator.Fragment
	candidateHash           parachaintypes.CandidateHash
	cumulativeModifications *inclusionemulator.ConstraintModifications
	parentHeadDataHash      common.Hash
	outputHeadDataHash      common.Hash
}

func (f *FragmentNode) relayParent() common.Hash {
	return f.fragment.RelayParent().Hash
}

// NewCandidateEntryFromFragment creates a candidate entry from a fragment, we dont need
// to perform the checks done in `NewCandidateEntry` since a `FragmentNode` always comes
// from a `CandidateEntry`
func NewCandidateEntryFromFragment(node *FragmentNode) *CandidateEntry {
	return &CandidateEntry{
		candidateHash:      node.candidateHash,
		parentHeadDataHash: node.parentHeadDataHash,
		outputHeadDataHash: node.outputHeadDataHash,
		candidate:          node.fragment.Candidate(),
		relayParent:        node.relayParent(),
		// a fragment node is always backed
		state: Backed,
	}
}

// BackedChain is a chain of backed/backable candidates
// Includes candidates pending availability and candidates which may be backed on-chain
type BackedChain struct {
	// holds the candidate chain
	chain []*FragmentNode

	// index from parent head data to the candidate that has that head data as parent
	// only contains the candidates present in the `chain`
	byParentHead map[common.Hash]parachaintypes.CandidateHash

	// index from head data hash to the candidate hash outputting that head data
	// only contains the candidates present in the `chain`
	byOutputHead map[common.Hash]parachaintypes.CandidateHash

	// a set of candidate hashes in the `chain`
	candidates map[parachaintypes.CandidateHash]struct{}
}

func NewBackedChain() *BackedChain {
	return &BackedChain{
		chain:        make([]*FragmentNode, 0),
		byParentHead: make(map[common.Hash]parachaintypes.CandidateHash),
		byOutputHead: make(map[common.Hash]parachaintypes.CandidateHash),
		candidates:   make(map[parachaintypes.CandidateHash]struct{}),
	}
}

func (bc *BackedChain) Push(candidate *FragmentNode) {
	bc.candidates[candidate.candidateHash] = struct{}{}
	bc.byParentHead[candidate.parentHeadDataHash] = candidate.candidateHash
	bc.byOutputHead[candidate.outputHeadDataHash] = candidate.candidateHash
	bc.chain = append(bc.chain, candidate)
}

func (bc *BackedChain) Clear() []*FragmentNode {
	bc.byParentHead = make(map[common.Hash]parachaintypes.CandidateHash)
	bc.byOutputHead = make(map[common.Hash]parachaintypes.CandidateHash)
	bc.candidates = make(map[parachaintypes.CandidateHash]struct{})

	oldChain := bc.chain
	bc.chain = nil
	return oldChain
}

func (bc *BackedChain) RevertToParentHash(parentHeadDataHash common.Hash) []*FragmentNode {
	foundIndex := -1

	for i := 0; i < len(bc.chain); i++ {
		node := bc.chain[i]

		if foundIndex != -1 {
			delete(bc.byParentHead, node.parentHeadDataHash)
			delete(bc.byOutputHead, node.outputHeadDataHash)
			delete(bc.candidates, node.candidateHash)
		} else if node.outputHeadDataHash == parentHeadDataHash {
			foundIndex = i
		}
	}

	if foundIndex != -1 {
		// drain the elements from the found index until
		// the end of the slice and return them
		removed := make([]*FragmentNode, len(bc.chain)-(foundIndex+1))
		copy(removed, bc.chain[foundIndex+1:])
		bc.chain = slices.Delete(bc.chain, foundIndex+1, len(bc.chain))

		return removed
	}

	return nil
}

func (bc *BackedChain) Contains(hash parachaintypes.CandidateHash) bool {
	_, ok := bc.candidates[hash]
	return ok
}

// this is a fragment chain specific to an active leaf. It holds the current
// best backable candidate chain, as well as potential candidates which could
// become connected to the chain in the future or which could even overwrite
// the existing chain
type FragmentChain struct {
	// the current scope, which dictates the on-chain operating constraints that
	// all future candidates must ad-here to.
	scope *Scope

	// the current best chain of backable candidates. It only contains candidates
	// which build on top of each other and which have reached the backing quorum.
	// In the presence of potential forks, this chain will pick a fork according to
	// the `forkSelectionRule`
	bestChain *BackedChain

	// the potential candidate storage. Contains candidates which are not yet part of
	// the `chain` but may become in the future. These can form any tree shape as well
	// as contain unconnected candidates for which we don't know the parent.
	unconnected *CandidateStorage
}

// NewFragmentChain createa a new fragment chain with the given scope and populates it with
// the candidates pending availability
func NewFragmentChain(scope *Scope, candidatesPendingAvailability *CandidateStorage) *FragmentChain {
	fragmentChain := &FragmentChain{
		scope:       scope,
		bestChain:   NewBackedChain(),
		unconnected: NewCandidateStorage(),
	}

	// we only need to populate the best backable chain. Candidates pending availability
	// must form a chain with the latest included head.
	fragmentChain.populateChain(candidatesPendingAvailability)
	return fragmentChain
}

// earliestRelayParent returns the earliest relay parent a new candidate can have in order
// to be added to the chain right now. This is the relay parent of the latest candidate in
// the chain. The value returned may not be valid if we want to add a candidate pending
// availability, which may have a relay parent which is out of scope, special handling
// is needed in that case.
func (f *FragmentChain) earliestRelayParent() *inclusionemulator.RelayChainBlockInfo {
	if len(f.bestChain.chain) > 0 {
		lastCandidate := f.bestChain.chain[len(f.bestChain.chain)-1]
		info := f.scope.Ancestor(lastCandidate.relayParent())
		if info != nil {
			return info
		}

		// if the relay parent is out of scope AND it is in the chain
		// it must be a candidate pending availability
		pending := f.scope.GetPendingAvailability(lastCandidate.candidateHash)
		if pending == nil {
			return nil
		}

		return &pending.RelayParent
	}

	earliest := f.scope.EarliestRelayParent()
	return &earliest
}

type possibleChild struct {
	fragment           *inclusionemulator.Fragment
	candidateHash      parachaintypes.CandidateHash
	outputHeadDataHash common.Hash
	parentHeadDataHash common.Hash
}

// populateChain populates the fragment chain with candidates from the supplied `CandidateStorage`.
// Can be called by the `NewFragmentChain` or when backing a new candidate. When this is called
// it may cause the previous chain to be completely erased or it may add more than one candidate
func (f *FragmentChain) populateChain(storage *CandidateStorage) {
	var cumulativeModifications *inclusionemulator.ConstraintModifications
	if len(f.bestChain.chain) > 0 {
		lastCandidate := f.bestChain.chain[len(f.bestChain.chain)-1]
		cumulativeModifications = lastCandidate.cumulativeModifications
	} else {
		cumulativeModifications = inclusionemulator.NewConstraintModificationsIdentity()
	}

	earliestRelayParent := f.earliestRelayParent()
	if earliestRelayParent == nil {
		return
	}

	for {
		if len(f.bestChain.chain) > int(f.scope.maxDepth) {
			break
		}

		childConstraints, err := f.scope.baseConstraints.ApplyModifications(cumulativeModifications)
		if err != nil {
			// TODO: include logger
			fmt.Println("failed to apply modifications:", err)
			break
		}

		requiredHeadHash, err := childConstraints.RequiredParent.Hash()
		if err != nil {
			fmt.Println("failed while hashing required parent:", err)
		}

		possibleChildren := make([]*possibleChild, 0)
		// select the few possible backed/backable children which can be added to the chain right now
		for candidateEntry := range storage.possibleBackedParaChildren(requiredHeadHash) {
			// only select a candidate if:
			// 1. it does not introduce a fork or a cycle
			// 2. parent hash is correct
			// 3. relay parent does not move backwards
			// 4. all non-pending-availability candidates have relay-parent in the scope
			// 5. candidate outputs fulfill constraints

			var relayParent inclusionemulator.RelayChainBlockInfo
			var minRelayParent uint

			pending := f.scope.GetPendingAvailability(candidateEntry.candidateHash)
			if pending != nil {
				relayParent = pending.RelayParent
				if len(f.bestChain.chain) == 0 {
					minRelayParent = pending.RelayParent.Number
				} else {
					minRelayParent = earliestRelayParent.Number
				}
			} else {
				info := f.scope.Ancestor(candidateEntry.relayParent)
				if info == nil {
					continue
				}

				relayParent = *info
				minRelayParent = earliestRelayParent.Number
			}

			if err := f.checkCyclesOrInvalidTree(candidateEntry.outputHeadDataHash); err != nil {
				fmt.Println("checking cycle or invalid tree:", err)
				continue
			}

			// require: candidates dont move backwards and only pending availability
			// candidates can be out-of-scope.
			//
			// earliest relay parent can be before the

			if relayParent.Number < minRelayParent {
				// relay parent moved backwards
				continue
			}

			// don't add candidates if they're already present in the chain
			// this can never happen, as candidates can only be duplicated
			// if there's a cycle and we shouldnt have allowed for a cycle
			// to be chained
			if f.bestChain.Contains(candidateEntry.candidateHash) {
				continue
			}

			constraints := childConstraints.Clone()
			if pending != nil {
				// overwrite for candidates pending availability as a special-case
				constraints.MinRelayParentNumber = pending.RelayParent.Number
			}

			fragment, err := inclusionemulator.NewFragment(relayParent, constraints, candidateEntry.candidate)
			if err != nil {
				fmt.Println("failed to create fragment:", err)
				continue
			}

			possibleChildren = append(possibleChildren, &possibleChild{
				fragment:           fragment,
				candidateHash:      candidateEntry.candidateHash,
				outputHeadDataHash: candidateEntry.outputHeadDataHash,
				parentHeadDataHash: candidateEntry.parentHeadDataHash,
			})
		}

		if len(possibleChildren) == 0 {
			break
		}

		// choose the best candidate
		bestCandidate := slices.MinFunc(possibleChildren, func(fst, snd *possibleChild) int {
			// always pick a candidate pending availability as best.
			if f.scope.GetPendingAvailability(fst.candidateHash) != nil {
				return -1
			} else if f.scope.GetPendingAvailability(snd.candidateHash) != nil {
				return 1
			} else {
				return forkSelectionRule(fst.candidateHash, snd.candidateHash)
			}
		})

		// remove the candidate from storage
		storage.removeCandidate(bestCandidate.candidateHash)

		// update the cumulative constraint modifications
		cumulativeModifications.Stack(bestCandidate.fragment.ConstraintModifications())

		// update the earliest relay parent
		earliestRelayParent = &inclusionemulator.RelayChainBlockInfo{
			Hash:        bestCandidate.fragment.RelayParent().Hash,
			Number:      bestCandidate.fragment.RelayParent().Number,
			StorageRoot: bestCandidate.fragment.RelayParent().StorageRoot,
		}

		node := &FragmentNode{
			fragment:                bestCandidate.fragment,
			candidateHash:           bestCandidate.candidateHash,
			parentHeadDataHash:      bestCandidate.parentHeadDataHash,
			outputHeadDataHash:      bestCandidate.outputHeadDataHash,
			cumulativeModifications: cumulativeModifications.Clone(),
		}

		// add the candidate to the chain now
		f.bestChain.Push(node)
	}
}

// checkCyclesOrInvalidTree checks whether a candidate outputting this head data would
// introduce a cycle or multiple paths to the same state. Trivial 0-length cycles are
// checked  in `NewCandidateEntry`.
func (f *FragmentChain) checkCyclesOrInvalidTree(outputHeadDataHash common.Hash) error {
	// this should catch a cycle where this candidate would point back to the parent
	// of some candidate in the chain
	_, ok := f.bestChain.byParentHead[outputHeadDataHash]
	if ok {
		return ErrCycle
	}

	// multiple paths to the same state, which cannot happen for a chain
	_, ok = f.bestChain.byOutputHead[outputHeadDataHash]
	if ok {
		return ErrMultiplePaths
	}

	return nil
}
