package inclusionemulator

import (
	"fmt"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/lib/common"
)

// ProspectiveCandidate includes key informations that represents a candidate
// without pinning it to a particular session. For example, commitments are
// represented here, but the erasure-root is not. This means that, prospective
// candidates are not correlated to any session in particular.
type ProspectiveCandidate struct {
	Commitments             parachaintypes.CandidateCommitments
	PersistedValidationData parachaintypes.PersistedValidationData
	PoVHash                 common.Hash
	ValidationCodeHash      parachaintypes.ValidationCodeHash
}

// ModificationError is kinds of errors that can happen when modifying constraints
type ModificationError interface {
	isModificationError()
}

var (
	_ ModificationError = (*DisallowedHrmpWatermark)(nil)
	_ ModificationError = (*NoSuchHrmpChannel)(nil)
	_ ModificationError = (*HrmpMessagesOverflow)(nil)
	_ ModificationError = (*HrmpBytesOverflow)(nil)
	_ ModificationError = (*UmpMessagesOverflow)(nil)
	_ ModificationError = (*UmpBytesOverflow)(nil)
	_ ModificationError = (*DmpMessagesUnderflow)(nil)
	_ ModificationError = (*AppliedNonexistentCodeUpgrade)(nil)
)

type DisallowedHrmpWatermark struct {
	blockNumber uint
}

func (*DisallowedHrmpWatermark) isModificationError() {}

func (e *DisallowedHrmpWatermark) String() string {
	return fmt.Sprintf("DisallowedHrmpWatermark(BlockNumber: %d)", e.blockNumber)
}

type NoSuchHrmpChannel struct {
	paraId parachaintypes.ParaID
}

func (*NoSuchHrmpChannel) isModificationError() {}

func (e *NoSuchHrmpChannel) String() string {
	return fmt.Sprintf("NoSuchHrmpChannel(ParaId: %d)", e.paraId)
}

type HrmpMessagesOverflow struct {
	paraId            parachaintypes.ParaID
	messagesRemaining uint
	messagesSubmitted uint
}

func (*HrmpMessagesOverflow) isModificationError() {}

func (e *HrmpMessagesOverflow) String() string {
	return fmt.Sprintf("HrmpMessagesOverflow(ParaId: %d, MessagesRemaining: %d, MessagesSubmitted: %d)", e.paraId, e.messagesRemaining, e.messagesSubmitted)
}

type HrmpBytesOverflow struct {
	paraId         parachaintypes.ParaID
	bytesRemaining uint
	bytesSubmitted uint
}

func (*HrmpBytesOverflow) isModificationError() {}

func (e *HrmpBytesOverflow) String() string {
	return fmt.Sprintf("HrmpBytesOverflow(ParaId: %d, BytesRemaining: %d, BytesSubmitted: %d)", e.paraId, e.bytesRemaining, e.bytesSubmitted)
}

type UmpMessagesOverflow struct {
	messagesRemaining uint
	messagesSubmitted uint
}

func (*UmpMessagesOverflow) isModificationError() {}

func (e *UmpMessagesOverflow) String() string {
	return fmt.Sprintf("UmpMessagesOverflow(MessagesRemaining: %d, MessagesSubmitted: %d)", e.messagesRemaining, e.messagesSubmitted)
}

type UmpBytesOverflow struct {
	bytesRemaining uint
	bytesSubmitted uint
}

func (*UmpBytesOverflow) isModificationError() {}

func (e *UmpBytesOverflow) String() string {
	return fmt.Sprintf("UmpBytesOverflow(BytesRemaining: %d, BytesSubmitted: %d)", e.bytesRemaining, e.bytesSubmitted)
}

type DmpMessagesUnderflow struct {
	messagesRemaining uint
	messagesProcessed uint
}

func (*DmpMessagesUnderflow) isModificationError() {}

func (e *DmpMessagesUnderflow) String() string {
	return fmt.Sprintf("DmpMessagesUnderflow(MessagesRemaining: %d, MessagesProcessed: %d)", e.messagesRemaining, e.messagesProcessed)
}

type AppliedNonexistentCodeUpgrade struct{}

func (*AppliedNonexistentCodeUpgrade) isModificationError() {}

func (e *AppliedNonexistentCodeUpgrade) String() string {
	return "AppliedNonexistentCodeUpgrade()"
}

// FragmentValidityError kinds of errors with the validity of a fragment.
type FragmentValidityError interface {
	isFragmentValidityError()
}

var (
	_ FragmentValidityError = (*ValidationCodeMismatch)(nil)
	_ FragmentValidityError = (*PersistedValidationDataMismatch)(nil)
	_ FragmentValidityError = (*OutputsInvalid)(nil)
	_ FragmentValidityError = (*CodeSizeTooLarge)(nil)
	_ FragmentValidityError = (*RelayParentTooOld)(nil)
	_ FragmentValidityError = (*DmpAdvancementRule)(nil)
	_ FragmentValidityError = (*UmpMessagesPerCandidateOverflow)(nil)
	_ FragmentValidityError = (*HrmpMessagesPerCandidateOverflow)(nil)
	_ FragmentValidityError = (*CodeUpgradeRestricted)(nil)
	_ FragmentValidityError = (*HrmpMessagesDescendingOrDuplicate)(nil)
)

type ValidationCodeMismatch struct {
	expected parachaintypes.ValidationCodeHash
	got      parachaintypes.ValidationCodeHash
}

func (*ValidationCodeMismatch) isFragmentValidityError() {}

func (e *ValidationCodeMismatch) String() string {
	return fmt.Sprintf("ValidationCodeMismatch(Expected: %s, Got: %s)", e.expected, e.got)
}

type PersistedValidationDataMismatch struct {
	expected parachaintypes.PersistedValidationData
	got      parachaintypes.PersistedValidationData
}

func (*PersistedValidationDataMismatch) isFragmentValidityError() {}

func (e *PersistedValidationDataMismatch) String() string {
	return fmt.Sprintf("PersistedValidationDataMismatch(Expected: %v, Got: %v)", e.expected, e.got)
}

type OutputsInvalid struct {
	modificationError ModificationError
}

func (*OutputsInvalid) isFragmentValidityError() {}

func (e *OutputsInvalid) String() string {
	return fmt.Sprintf("OutputsInvalid(ModificationError: %v)", e.modificationError)
}

type CodeSizeTooLarge struct {
	maxAllowed uint
	newSize    uint
}

func (*CodeSizeTooLarge) isFragmentValidityError() {}

func (e *CodeSizeTooLarge) String() string {
	return fmt.Sprintf("CodeSizeTooLarge(MaxAllowed: %d, NewSize: %d)", e.maxAllowed, e.newSize)
}

type RelayParentTooOld struct {
	minAllowed uint
	current    uint
}

func (*RelayParentTooOld) isFragmentValidityError() {}

func (e *RelayParentTooOld) String() string {
	return fmt.Sprintf("RelayParentTooOld(MinAllowed: %d, Current: %d)", e.minAllowed, e.current)
}

type DmpAdvancementRule struct{}

func (*DmpAdvancementRule) isFragmentValidityError() {}

func (e *DmpAdvancementRule) String() string {
	return "DmpAdvancementRule()"
}

type UmpMessagesPerCandidateOverflow struct {
	messagesAllowed   uint
	messagesSubmitted uint
}

func (*UmpMessagesPerCandidateOverflow) isFragmentValidityError() {}

func (e *UmpMessagesPerCandidateOverflow) String() string {
	return fmt.Sprintf("UmpMessagesPerCandidateOverflow(MessagesAllowed: %d, MessagesSubmitted: %d)", e.messagesAllowed, e.messagesSubmitted)
}

type HrmpMessagesPerCandidateOverflow struct {
	messagesAllowed   uint
	messagesSubmitted uint
}

func (*HrmpMessagesPerCandidateOverflow) isFragmentValidityError() {}

func (e *HrmpMessagesPerCandidateOverflow) String() string {
	return fmt.Sprintf("HrmpMessagesPerCandidateOverflow(MessagesAllowed: %d, MessagesSubmitted: %d)", e.messagesAllowed, e.messagesSubmitted)
}

type CodeUpgradeRestricted struct{}

func (*CodeUpgradeRestricted) isFragmentValidityError() {}

func (e *CodeUpgradeRestricted) String() string {
	return "CodeUpgradeRestricted()"
}

type HrmpMessagesDescendingOrDuplicate struct {
	index uint
}

func (*HrmpMessagesDescendingOrDuplicate) isFragmentValidityError() {}

func (e *HrmpMessagesDescendingOrDuplicate) String() string {
	return fmt.Sprintf("HrmpMessagesDescendingOrDuplicate(Index: %d)", e.index)
}
