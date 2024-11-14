package inclusionemulator

import (
	"bytes"
	"errors"
	"fmt"
	"iter"

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

type ErrDisallowedHrmpWatermark struct {
	blockNumber uint
}

func (e *ErrDisallowedHrmpWatermark) Error() string {
	return fmt.Sprintf("DisallowedHrmpWatermark(BlockNumber: %d)", e.blockNumber)
}

type ErrNoSuchHrmpChannel struct {
	paraId parachaintypes.ParaID
}

func (e *ErrNoSuchHrmpChannel) Error() string {
	return fmt.Sprintf("NoSuchHrmpChannel(ParaId: %d)", e.paraId)
}

type ErrHrmpMessagesOverflow struct {
	paraId            parachaintypes.ParaID
	messagesRemaining uint
	messagesSubmitted uint
}

func (e *ErrHrmpMessagesOverflow) Error() string {
	return fmt.Sprintf("HrmpMessagesOverflow(ParaId: %d, MessagesRemaining: %d, MessagesSubmitted: %d)", e.paraId, e.messagesRemaining, e.messagesSubmitted)
}

type ErrHrmpBytesOverflow struct {
	paraId         parachaintypes.ParaID
	bytesRemaining uint
	bytesSubmitted uint
}

func (e *ErrHrmpBytesOverflow) Error() string {
	return fmt.Sprintf("HrmpBytesOverflow(ParaId: %d, BytesRemaining: %d, BytesSubmitted: %d)", e.paraId, e.bytesRemaining, e.bytesSubmitted)
}

type ErrUmpMessagesOverflow struct {
	messagesRemaining uint
	messagesSubmitted uint
}

func (e *ErrUmpMessagesOverflow) Error() string {
	return fmt.Sprintf("UmpMessagesOverflow(MessagesRemaining: %d, MessagesSubmitted: %d)", e.messagesRemaining, e.messagesSubmitted)
}

type ErrUmpBytesOverflow struct {
	bytesRemaining uint
	bytesSubmitted uint
}

func (e *ErrUmpBytesOverflow) Error() string {
	return fmt.Sprintf("UmpBytesOverflow(BytesRemaining: %d, BytesSubmitted: %d)", e.bytesRemaining, e.bytesSubmitted)
}

type ErrDmpMessagesUnderflow struct {
	messagesRemaining uint
	messagesProcessed uint
}

func (e *ErrDmpMessagesUnderflow) Error() string {
	return fmt.Sprintf("DmpMessagesUnderflow(MessagesRemaining: %d, MessagesProcessed: %d)", e.messagesRemaining, e.messagesProcessed)
}

var (
	ErrAppliedNonexistentCodeUpgrade = errors.New("AppliedNonexistentCodeUpgrade()")
	ErrDmpAdvancementRule            = errors.New("DmpAdvancementRule()")
	ErrCodeUpgradeRestricted         = errors.New("CodeUpgradeRestricted()")
)

type ErrValidationCodeMismatch struct {
	expected parachaintypes.ValidationCodeHash
	got      parachaintypes.ValidationCodeHash
}

func (e *ErrValidationCodeMismatch) Error() string {
	return fmt.Sprintf("ValidationCodeMismatch(Expected: %s, Got: %s)", e.expected, e.got)
}

type ErrPersistedValidationDataMismatch struct {
	expected parachaintypes.PersistedValidationData
	got      parachaintypes.PersistedValidationData
}

func (e *ErrPersistedValidationDataMismatch) Error() string {
	return fmt.Sprintf("PersistedValidationDataMismatch(Expected: %v, Got: %v)", e.expected, e.got)
}

type ErrOutputsInvalid struct {
	modificationError error
}

func (e *ErrOutputsInvalid) Error() string {
	return fmt.Sprintf("OutputsInvalid(ModificationError: %v)", e.modificationError)
}

type ErrCodeSizeTooLarge struct {
	maxAllowed uint
	newSize    uint
}

func (e *ErrCodeSizeTooLarge) Error() string {
	return fmt.Sprintf("CodeSizeTooLarge(MaxAllowed: %d, NewSize: %d)", e.maxAllowed, e.newSize)
}

type ErrRelayParentTooOld struct {
	minAllowed uint
	current    uint
}

func (e *ErrRelayParentTooOld) Error() string {
	return fmt.Sprintf("RelayParentTooOld(MinAllowed: %d, Current: %d)", e.minAllowed, e.current)
}

type ErrUmpMessagesPerCandidateOverflow struct {
	messagesAllowed   uint
	messagesSubmitted uint
}

func (e *ErrUmpMessagesPerCandidateOverflow) Error() string {
	return fmt.Sprintf("UmpMessagesPerCandidateOverflow(MessagesAllowed: %d, MessagesSubmitted: %d)", e.messagesAllowed, e.messagesSubmitted)
}

type ErrHrmpMessagesPerCandidateOverflow struct {
	messagesAllowed   uint
	messagesSubmitted uint
}

func (e *ErrHrmpMessagesPerCandidateOverflow) Error() string {
	return fmt.Sprintf("HrmpMessagesPerCandidateOverflow(MessagesAllowed: %d, MessagesSubmitted: %d)", e.messagesAllowed, e.messagesSubmitted)
}

type ErrHrmpMessagesDescendingOrDuplicate struct {
	index uint
}

func (e *ErrHrmpMessagesDescendingOrDuplicate) Error() string {
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
	modifications        *ConstraintModifications
}

// NewFragment creates a new Fragment. This fails if the fragment isnt in line
// with the operating constraints. That is, either its inputs or outputs fail
// checks against the constraints.
// This does not check that the collator signature is valid or wheter the PoV is
// small enough.
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
) (*ConstraintModifications, error) {
	upwardMessages := make([]parachaintypes.UpwardMessage, 0)
	// filter UMP signals
	for upwardMessage := range skipUmpSignals(commitments.UpwardMessages) {
		upwardMessages = append(upwardMessages, upwardMessage)
	}

	umpMessagesSent := len(upwardMessages)
	umpBytesSent := 0
	for _, message := range upwardMessages {
		umpBytesSent += len(message)
	}

	hrmpWatermark := HrmpWatermarkUpdate{
		Type:  Trunk,
		Block: uint(commitments.HrmpWatermark),
	}

	if uint(commitments.HrmpWatermark) == relayParent.Number {
		hrmpWatermark.Type = Head
	}

	outboundHrmp := make(map[parachaintypes.ParaID]OutboundHrmpChannelModification)
	var lastRecipient *parachaintypes.ParaID

	for i, message := range commitments.HorizontalMessages {
		if lastRecipient != nil && *lastRecipient >= parachaintypes.ParaID(message.Recipient) {
			return nil, &ErrHrmpMessagesDescendingOrDuplicate{index: uint(i)}
		}

		recipientParaID := parachaintypes.ParaID(message.Recipient)
		lastRecipient = &recipientParaID
		record, ok := outboundHrmp[recipientParaID]
		if !ok {
			record = OutboundHrmpChannelModification{}
		}

		record.BytesSubmitted += uint(len(message.Data))
		record.MessagesSubmitted++
		outboundHrmp[recipientParaID] = record
	}

	codeUpgradeApplied := false
	if operatingConstraints.FutureValidationCode != nil {
		codeUpgradeApplied = relayParent.Number >= operatingConstraints.FutureValidationCode.BlockNumber
	}

	modifications := &ConstraintModifications{
		RequiredParent:       &commitments.HeadData,
		HrmpWatermark:        &hrmpWatermark,
		OutboundHrmp:         outboundHrmp,
		UmpMessagesSent:      uint(umpMessagesSent),
		UmpBytesSent:         uint(umpBytesSent),
		DmpMessagesProcessed: uint(commitments.ProcessedDownwardMessages),
		CodeUpgradeApplied:   codeUpgradeApplied,
	}

	err := validateAgainstConstraints(
		operatingConstraints,
		relayParent,
		commitments,
		persistedValidationData,
		validationCodeHash,
		modifications,
	)
	if err != nil {
		return nil, err
	}

	return modifications, nil
}

// UmpSeparator is a constant used to separate UMP signals.
var UmpSeparator = []byte{}

// skipUmpSignals is a utility function for skipping the UMP signals.
func skipUmpSignals(upwardMessages []parachaintypes.UpwardMessage) iter.Seq[parachaintypes.UpwardMessage] {
	return func(yield func(parachaintypes.UpwardMessage) bool) {
		for _, message := range upwardMessages {
			if !bytes.Equal([]byte(message), UmpSeparator) {
				if !yield([]byte(message)) {
					return
				}
			}
			return
		}
	}
}
