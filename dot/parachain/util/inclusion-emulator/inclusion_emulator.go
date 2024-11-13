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
// TODO: should we have a specialized struct to simulate an Arc<ProspectiveCandidate>?
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

// RelayChainBlockInfo contains minimum information about a relay-chain block.
type RelayChainBlockInfo struct {
	Hash        common.Hash
	StorageRoot common.Hash
	Number      uint
}

// Constraints on the actions that can be taken by a new parachain block. These
// limitations are implicitly associated with some particular parachain, which should
// be apparent from usage.
type Constraints struct {
	// The minimum relay-parent number accepted under these constraints.
	MinRelayParentNumber uint
	// The maximum Proof-of-Validity size allowed, in bytes.
	MaxPoVSize uint
	// The maximum new validation code size allowed, in bytes.
	MaxCodeSize uint
	// The amount of UMP messages remaining.
	UmpRemaining uint
	// The amount of UMP bytes remaining.
	UmpRemainingBytes uint
	// The maximum number of UMP messages allowed per candidate.
	MaxUmpNumPerCandidate uint
	// Remaining DMP queue. Only includes sent-at block numbers.
	DmpRemainingMessages []uint
	// The limitations of all registered inbound HRMP channels.
	HrmpInbound InboundHrmpLimitations
	// The limitations of all registered outbound HRMP channels.
	HrmpChannelsOut map[parachaintypes.ParaID]OutboundHrmpChannelLimitations
	// The maximum number of HRMP messages allowed per candidate.
	MaxHrmpNumPerCandidate uint
	// The required parent head-data of the parachain.
	RequiredParent parachaintypes.HeadData
	// The expected validation-code-hash of this parachain.
	ValidationCodeHash parachaintypes.ValidationCodeHash
	// The code upgrade restriction signal as-of this parachain.
	UpgradeRestriction parachaintypes.UpgradeRestriction
	// The future validation code hash, if any, and at what relay-parent
	// number the upgrade would be minimally applied.
	FutureValidationCode *FutureValidationCode
}

func FromPrimitiveConstraints(pc parachaintypes.Constraints) *Constraints {
	hrmpChannelsOut := make(map[parachaintypes.ParaID]OutboundHrmpChannelLimitations)
	for k, v := range pc.HrmpChannelsOut {
		hrmpChannelsOut[k] = OutboundHrmpChannelLimitations{
			BytesRemaining:    uint(v.BytesRemaining),
			MessagesRemaining: uint(v.MessagesRemaining),
		}
	}

	var futureValidationCode *FutureValidationCode
	if pc.FutureValidationCode != nil {
		futureValidationCode = &FutureValidationCode{
			BlockNumber:        pc.FutureValidationCode.BlockNumber,
			ValidationCodeHash: pc.FutureValidationCode.ValidationCodeHash,
		}
	}

	return &Constraints{
		MinRelayParentNumber:  pc.MinRelayParentNumber,
		MaxPoVSize:            uint(pc.MaxPoVSize),
		MaxCodeSize:           uint(pc.MaxCodeSize),
		UmpRemaining:          uint(pc.UmpRemaining),
		UmpRemainingBytes:     uint(pc.UmpRemainingBytes),
		MaxUmpNumPerCandidate: uint(pc.MaxUmpNumPerCandidate),
		DmpRemainingMessages:  pc.DmpRemainingMessages,
		HrmpInbound: InboundHrmpLimitations{
			ValidWatermarks: pc.HrmpInbound.ValidWatermarks,
		},
		HrmpChannelsOut:        hrmpChannelsOut,
		MaxHrmpNumPerCandidate: uint(pc.MaxHrmpNumPerCandidate),
		RequiredParent:         pc.RequiredParent,
		ValidationCodeHash:     pc.ValidationCodeHash,
		UpgradeRestriction:     pc.UpgradeRestriction,
		FutureValidationCode:   futureValidationCode,
	}
}

// InboundHrmpLimitations constraints on inbound HRMP channels
type InboundHrmpLimitations struct {
	ValidWatermarks []uint
}

// OutboundHrmpChannelLimitations constraints on outbound HRMP channels.
type OutboundHrmpChannelLimitations struct {
	BytesRemaining    uint
	MessagesRemaining uint
}

// FutureValidationCode represents the future validation code hash, if any, and at what relay-parent
// number the upgrade would be minimally applied.
type FutureValidationCode struct {
	BlockNumber        uint
	ValidationCodeHash parachaintypes.ValidationCodeHash
}

// OutboundHrmpChannelModification represents modifications to outbound HRMP channels.
type OutboundHrmpChannelModification struct {
	BytesSubmitted    uint
	MessagesSubmitted uint
}

// HrmpWatermarkUpdate represents an update to the HRMP Watermark.
type HrmpWatermarkUpdate struct {
	Type  HrmpWatermarkUpdateType
	Block uint
}

// HrmpWatermarkUpdateType defines the type of HrmpWatermarkUpdate.
type HrmpWatermarkUpdateType int

const (
	Head HrmpWatermarkUpdateType = iota
	Trunk
)

// Watermark returns the block number of the HRMP Watermark update.
func (h HrmpWatermarkUpdate) Watermark() uint {
	return h.Block
}

// ConstraintModifications represents modifications to constraints as a result of prospective candidates.
type ConstraintModifications struct {
	// The required parent head to build upon.
	RequiredParent *parachaintypes.HeadData
	// The new HRMP watermark.
	HrmpWatermark *HrmpWatermarkUpdate
	// Outbound HRMP channel modifications.
	OutboundHrmp map[parachaintypes.ParaID]OutboundHrmpChannelModification
	// The amount of UMP XCM messages sent. `UMPSignal` and separator are excluded.
	UmpMessagesSent uint
	// The amount of UMP XCM bytes sent. `UMPSignal` and separator are excluded.
	UmpBytesSent uint
	// The amount of DMP messages processed.
	DmpMessagesProcessed uint
	// Whether a pending code upgrade has been applied.
	CodeUpgradeApplied bool
}

// Identity returns the 'identity' modifications: these can be applied to
// any constraints and yield the exact same result.
func NewConstraintModificationsIdentity() ConstraintModifications {
	return ConstraintModifications{
		RequiredParent:       nil,
		HrmpWatermark:        nil,
		OutboundHrmp:         make(map[parachaintypes.ParaID]OutboundHrmpChannelModification),
		UmpMessagesSent:      0,
		UmpBytesSent:         0,
		DmpMessagesProcessed: 0,
		CodeUpgradeApplied:   false,
	}
}

// Stack stacks other modifications on top of these. This does no sanity-checking, so if
// `other` is garbage relative to `self`, then the new value will be garbage as well.
// This is an addition which is not commutative.
func (cm *ConstraintModifications) Stack(other *ConstraintModifications) {
	if other.RequiredParent != nil {
		cm.RequiredParent = other.RequiredParent
	}

	if other.HrmpWatermark != nil {
		cm.HrmpWatermark = other.HrmpWatermark
	}

	for id, mods := range other.OutboundHrmp {
		record, ok := cm.OutboundHrmp[id]
		if !ok {
			record = OutboundHrmpChannelModification{}
		}

		record.BytesSubmitted += mods.BytesSubmitted
		record.MessagesSubmitted += mods.MessagesSubmitted
		cm.OutboundHrmp[id] = record
	}

	cm.UmpMessagesSent += other.UmpMessagesSent
	cm.UmpBytesSent += other.UmpBytesSent
	cm.DmpMessagesProcessed += other.DmpMessagesProcessed
	cm.CodeUpgradeApplied = cm.CodeUpgradeApplied || other.CodeUpgradeApplied
}

// Fragment represents another prospective parachain block
// This is a type which guarantees that the candidate is valid under the operating constraints
type Fragment struct {
	relayParent          RelayChainBlockInfo
	operatingConstraints Constraints
	candidate            ProspectiveCandidate
	modifications        ConstraintModifications
}

func NewFragment(
	relayParent RelayChainBlockInfo,
	operatingConstraints Constraints,
	candidate ProspectiveCandidate) (*Fragment, error) {
	modifications, err := checkAgainstConstraints(
		relayParent,
		operatingConstraints,
		candidate.Commitments,
		candidate.ValidationCodeHash,
		candidate.PersistedValidationData,
	)
	if err != nil {
		return nil, err
	}

	return &Fragment{
		relayParent:          relayParent,
		operatingConstraints: operatingConstraints,
		candidate:            candidate,
		modifications:        modifications,
	}, nil
}

func checkAgainstConstraints(
	relayParent RelayChainBlockInfo,
	operatingConstraints Constraints,
	commitments parachaintypes.CandidateCommitments,
	validationCodeHash parachaintypes.ValidationCodeHash,
	persistedValidationData parachaintypes.PersistedValidationData,
) (ConstraintModifications, error) {
	return ConstraintModifications{}, nil
}
