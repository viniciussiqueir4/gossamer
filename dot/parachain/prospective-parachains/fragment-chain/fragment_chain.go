package fragmentchain

import (
	"fmt"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	inclusionemulator "github.com/ChainSafe/gossamer/dot/parachain/util/inclusion-emulator"
	"github.com/ChainSafe/gossamer/lib/common"
)

type CandidateState int

const (
	Seconded CandidateState = iota
	Backed
)

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
	byCandidateHash map[parachaintypes.CandidateHash]CandidateEntry
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

func (c *CandidateStorage) addCandidateEntry(candidate *CandidateEntry) error {
	_, ok := c.byCandidateHash[candidate.candidateHash]
	if ok {
		return ErrCandidateAlradyKnown
	}

	// updates the reference parent hash -> candidate
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

}
