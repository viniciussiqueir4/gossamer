package prospectiveparachains

import (
	"context"
	"testing"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/stretchr/testify/assert"
)

const MAX_POV_SIZE = 1_000_000

func dummyPVD(parentHead parachaintypes.HeadData, relayParentNumber uint32) parachaintypes.PersistedValidationData {
	return parachaintypes.PersistedValidationData{
		ParentHead:             parentHead,
		RelayParentNumber:      relayParentNumber,
		RelayParentStorageRoot: common.EmptyHash,
		MaxPovSize:             MAX_POV_SIZE,
	}
}

func dummyCandidateReceiptBadSig(
	relayParentHash common.Hash,
	commitments *common.Hash,
) parachaintypes.CandidateReceipt {
	var commitmentsHash common.Hash

	if commitments != nil {
		commitmentsHash = *commitments
	} else {
		// Handle the case where commitments is nil
		// might want to use a default hash or the relayParentHash
		commitmentsHash = relayParentHash
	}

	return parachaintypes.CandidateReceipt{
		CommitmentsHash: commitmentsHash,
	}
}

func MakeCandidate(
	relayParent common.Hash,
	relayParentNumber uint32,
	paraID parachaintypes.ParaID,
	parentHead parachaintypes.HeadData,
	headData parachaintypes.HeadData,
	validationCodeHash parachaintypes.ValidationCodeHash,
) parachaintypes.CommittedCandidateReceipt {
	pvd := dummyPVD(parentHead, relayParentNumber)

	commitments := parachaintypes.CandidateCommitments{
		HeadData:                  headData,
		HorizontalMessages:        []parachaintypes.OutboundHrmpMessage{},
		UpwardMessages:            []parachaintypes.UpwardMessage{},
		NewValidationCode:         nil,
		ProcessedDownwardMessages: 0,
		HrmpWatermark:             relayParentNumber,
	}

	commitmentsHash := commitments.Hash()

	candidate := dummyCandidateReceiptBadSig(relayParent, &commitmentsHash)
	candidate.CommitmentsHash = commitments.Hash()
	candidate.Descriptor.ParaID = paraID

	pvdh, err := pvd.Hash()

	if err != nil {
		panic(err)
	}

	candidate.Descriptor.PersistedValidationDataHash = pvdh
	candidate.Descriptor.ValidationCodeHash = validationCodeHash

	result := parachaintypes.CommittedCandidateReceipt{
		Descriptor:  candidate.Descriptor,
		Commitments: commitments,
	}

	return result
}

func introduceSecondedCandidate(
	t *testing.T,
	overseerToSubsystem chan any,
	candidate parachaintypes.CommittedCandidateReceipt,
	pvd parachaintypes.PersistedValidationData,
) {
	req := IntroduceSecondedCandidateRequest{
		CandidateParaID:         candidate.Descriptor.ParaID,
		CandidateReceipt:        candidate,
		PersistedValidationData: pvd,
	}

	response := make(chan bool)

	msg := IntroduceSecondedCandidate{
		IntroduceSecondedCandidateRequest: req,
		Response:                          response,
	}

	overseerToSubsystem <- msg

	assert.True(t, <-response)
}

func introduceSecondedCandidateFailed(
	overseeChan chan any,
	candidate parachaintypes.CommittedCandidateReceipt,
	pvd parachaintypes.PersistedValidationData,
) {
	req := IntroduceSecondedCandidateRequest{
		CandidateParaID:         candidate.Descriptor.ParaID,
		CandidateReceipt:        candidate,
		PersistedValidationData: pvd,
	}

	response := make(chan bool)

	msg := IntroduceSecondedCandidate{
		IntroduceSecondedCandidateRequest: req,
	}

	msg.Response = response

	response <- false
}

func TestHandleIntroduceSecondedCandidate(
	t *testing.T,
) {
	candidateRelayParent := common.Hash{0x01}
	paraId := parachaintypes.ParaID(1)
	parentHead := parachaintypes.HeadData{}
	headData := parachaintypes.HeadData{}
	validationCodeHash := parachaintypes.ValidationCodeHash{0x01}
	candidateRelayParentNumber := uint32(1)

	candidate := MakeCandidate(
		candidateRelayParent,
		candidateRelayParentNumber,
		paraId,
		parentHead,
		headData,
		validationCodeHash,
	)

	pvd := dummyPVD(parentHead, candidateRelayParentNumber)

	subsystemToOverseer := make(chan any)
	overseerToSubsystem := make(chan any)

	prospectiveParachains := NewProspectiveParachains(subsystemToOverseer)

	prospectiveParachains.Run(context.Background(), overseerToSubsystem)

	introduceSecondedCandidate(t, overseerToSubsystem, candidate, pvd)
}
