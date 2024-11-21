// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package collatorprotocol

import (
	"sync"
	"testing"

	"github.com/ChainSafe/gossamer/dot/network"
	"github.com/ChainSafe/gossamer/dot/parachain/backing"
	collatorprotocolmessages "github.com/ChainSafe/gossamer/dot/parachain/collator-protocol/messages"
	networkbridgeevents "github.com/ChainSafe/gossamer/dot/parachain/network-bridge/events"
	networkbridgemessages "github.com/ChainSafe/gossamer/dot/parachain/network-bridge/messages"
	"github.com/ChainSafe/gossamer/dot/parachain/overseer"
	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/dot/peerset"
	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func TestProcessOverseerMessage(t *testing.T) {
	t.Parallel()

	var testCollatorID parachaintypes.CollatorID
	tempCollatID := common.MustHexToBytes("0x48215b9d322601e5b1a95164cea0dc4626f545f98343d07f1551eb9543c4b147")
	copy(testCollatorID[:], tempCollatID)
	peerID := peer.ID("testPeerID")
	testRelayParent := getDummyHash(5)

	commitments := parachaintypes.CandidateCommitments{
		UpwardMessages:    []parachaintypes.UpwardMessage{{1, 2, 3}},
		NewValidationCode: &parachaintypes.ValidationCode{1, 2, 3},
		HeadData: parachaintypes.HeadData{
			Data: []byte{1, 2, 3},
		},
		ProcessedDownwardMessages: uint32(5),
		HrmpWatermark:             uint32(0),
	}

	testCandidateReceipt := parachaintypes.CandidateReceipt{
		Descriptor: parachaintypes.CandidateDescriptor{
			ParaID:                      1000,
			RelayParent:                 common.MustHexToHash("0xded542bacb3ca6c033a57676f94ae7c8f36834511deb44e3164256fd3b1c0de0"), //nolint:lll
			Collator:                    testCollatorID,
			PersistedValidationDataHash: common.MustHexToHash("0x690d8f252ef66ab0f969c3f518f90012b849aa5ac94e1752c5e5ae5a8996de37"), //nolint:lll
			PovHash:                     common.MustHexToHash("0xe7df1126ac4b4f0fb1bc00367a12ec26ca7c51256735a5e11beecdc1e3eca274"), //nolint:lll
			ErasureRoot:                 common.MustHexToHash("0xc07f658163e93c45a6f0288d229698f09c1252e41076f4caa71c8cbc12f118a1"), //nolint:lll
			ParaHead:                    common.MustHexToHash("0x9a8a7107426ef873ab89fc8af390ec36bdb2f744a9ff71ad7f18a12d55a7f4f5"), //nolint:lll
		},

		CommitmentsHash: commitments.Hash(),
	}

	vdt := parachaintypes.NewStatementVDT()
	vdt.SetValue(parachaintypes.Seconded(
		parachaintypes.CommittedCandidateReceipt{
			Descriptor:  testCandidateReceipt.Descriptor,
			Commitments: commitments,
		},
	))
	testValidStatement := parachaintypes.SignedFullStatement{
		Payload: vdt,
	}

	testCases := []struct {
		description                     string
		msg                             any
		peerData                        map[peer.ID]PeerData
		expectedMessageCounts           int
		expectedNetworkBridgeSenderMsgs []any
		fetchedCandidates               map[string]CollationEvent
		deletesFetchCandidate           bool
		errString                       string
	}{
		{
			description: "CollateOn message fails with message not expected",
			msg:         collatorprotocolmessages.CollateOn(2),
			errString:   ErrNotExpectedOnValidatorSide.Error(),
		},
		{
			description: "DistributeCollation message fails with message not expected",
			msg:         collatorprotocolmessages.DistributeCollation{},
			errString:   ErrNotExpectedOnValidatorSide.Error(),
		},
		{
			description: "ReportCollator message fails with peer not found for collator",
			msg:         collatorprotocolmessages.ReportCollator(testCollatorID),
			errString:   ErrPeerIDNotFoundForCollator.Error(),
		},
		{
			description:           "ReportCollator message succeeds and reports a bad collator",
			msg:                   collatorprotocolmessages.ReportCollator(testCollatorID),
			expectedMessageCounts: 1,
			expectedNetworkBridgeSenderMsgs: []any{networkbridgemessages.ReportPeer{
				ReputationChange: peerset.ReputationChange{
					Value:  peerset.ReportBadCollatorValue,
					Reason: peerset.ReportBadCollatorReason,
				},
				PeerID: peerID,
			}},
			peerData: map[peer.ID]PeerData{
				peerID: {
					view: parachaintypes.View{},
					state: PeerStateInfo{
						PeerState: Collating,
						CollatingPeerState: CollatingPeerState{
							CollatorID: testCollatorID,
							ParaID:     6,
						},
					},
				},
			},
			errString: "",
		},
		{
			description: "InvalidOverseerMsg message fails with peer not found for collator",
			msg: collatorprotocolmessages.Invalid{
				Parent:           testRelayParent,
				CandidateReceipt: testCandidateReceipt,
			},
			expectedMessageCounts: 0,
			fetchedCandidates: func() map[string]CollationEvent {
				fetchedCollation, err := newFetchedCollationInfo(testCandidateReceipt)
				require.NoError(t, err)

				return map[string]CollationEvent{
					fetchedCollation.String(): {
						CollatorId: testCandidateReceipt.Descriptor.Collator,
						PendingCollation: PendingCollation{
							CommitmentHash: &testCandidateReceipt.CommitmentsHash,
						},
					},
				}
			}(),
			deletesFetchCandidate: true,
			errString:             ErrPeerIDNotFoundForCollator.Error(),
		},
		{
			description: "InvalidOverseerMsg message succeeds, reports a bad collator and removes fetchedCandidate",
			msg: collatorprotocolmessages.Invalid{
				Parent:           testRelayParent,
				CandidateReceipt: testCandidateReceipt,
			},
			expectedMessageCounts: 1,
			expectedNetworkBridgeSenderMsgs: []any{networkbridgemessages.ReportPeer{
				ReputationChange: peerset.ReputationChange{
					Value:  peerset.ReportBadCollatorValue,
					Reason: peerset.ReportBadCollatorReason,
				},
				PeerID: peerID,
			}},
			fetchedCandidates: func() map[string]CollationEvent {
				fetchedCollation, err := newFetchedCollationInfo(testCandidateReceipt)
				require.NoError(t, err)

				return map[string]CollationEvent{
					fetchedCollation.String(): {
						CollatorId: testCandidateReceipt.Descriptor.Collator,
						PendingCollation: PendingCollation{
							CommitmentHash: &testCandidateReceipt.CommitmentsHash,
						},
					},
				}
			}(),
			peerData: map[peer.ID]PeerData{
				peerID: {
					view: parachaintypes.View{},
					state: PeerStateInfo{
						PeerState: Collating,
						CollatingPeerState: CollatingPeerState{
							CollatorID: testCollatorID,
							ParaID:     6,
						},
					},
				},
			},
			deletesFetchCandidate: true,
			errString:             "",
		},
		{
			description: "SecondedOverseerMsg message fails with peer not found for collator and removes fetchedCandidate",
			msg: collatorprotocolmessages.Seconded{
				Parent: testRelayParent,
				Stmt:   testValidStatement,
			},
			fetchedCandidates: func() map[string]CollationEvent {
				fetchedCollation, err := newFetchedCollationInfo(testCandidateReceipt)
				require.NoError(t, err)
				return map[string]CollationEvent{
					fetchedCollation.String(): {
						CollatorId: testCandidateReceipt.Descriptor.Collator,
						PendingCollation: PendingCollation{
							CommitmentHash: &testCandidateReceipt.CommitmentsHash,
						},
					},
				}
			}(),
			expectedMessageCounts: 0,
			deletesFetchCandidate: true,
			errString:             ErrPeerIDNotFoundForCollator.Error(),
		},
		{
			description: "SecondedOverseerMsg message succceds, reports a good collator and removes fetchedCandidate",
			msg: collatorprotocolmessages.Seconded{
				Parent: testRelayParent,
				Stmt:   testValidStatement,
			},
			expectedMessageCounts: 2,
			expectedNetworkBridgeSenderMsgs: []any{
				networkbridgemessages.ReportPeer{
					ReputationChange: peerset.ReputationChange{
						Value:  peerset.BenefitNotifyGoodValue,
						Reason: peerset.BenefitNotifyGoodReason,
					},
					PeerID: peerID,
				},
				networkbridgemessages.SendCollationMessage{
					To: []peer.ID{peerID},
					CollationProtocolMessage: func() collatorprotocolmessages.CollationProtocol {
						collatorProtocolMessage := collatorprotocolmessages.NewCollatorProtocolMessage()
						err := collatorProtocolMessage.SetValue(collatorprotocolmessages.CollationSeconded{
							RelayParent: testRelayParent,
							Statement:   parachaintypes.UncheckedSignedFullStatement(testValidStatement),
						})
						require.NoError(t, err)
						collationMessage := collatorprotocolmessages.NewCollationProtocol()

						err = collationMessage.SetValue(collatorProtocolMessage)
						require.NoError(t, err)

						return collationMessage
					}(),
				},
			},
			fetchedCandidates: func() map[string]CollationEvent {
				fetchedCollation, err := newFetchedCollationInfo(testCandidateReceipt)
				require.NoError(t, err)
				return map[string]CollationEvent{
					fetchedCollation.String(): {
						CollatorId: testCandidateReceipt.Descriptor.Collator,
						PendingCollation: PendingCollation{
							CommitmentHash: &testCandidateReceipt.CommitmentsHash,
						},
					},
				}
			}(),
			peerData: map[peer.ID]PeerData{
				peerID: {
					view: parachaintypes.View{},
					state: PeerStateInfo{
						PeerState: Collating,
						CollatingPeerState: CollatingPeerState{
							CollatorID: testCollatorID,
							ParaID:     6,
						},
					},
				},
			},
			deletesFetchCandidate: true,
			errString:             "",
		},
	}
	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			subSystemToOverseer := make(chan any)
			cpvs := CollatorProtocolValidatorSide{
				SubSystemToOverseer: subSystemToOverseer,
				fetchedCandidates:   c.fetchedCandidates,
				peerData:            c.peerData,
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			var wg sync.WaitGroup
			wg.Add(1)

			go func(expectedNetworkBridgeSenderMsgs []any) {
				var actual []any
				for i := 0; i < len(expectedNetworkBridgeSenderMsgs); i++ {
					actual = append(actual, <-subSystemToOverseer)
				}

				testCompareNetworkBridgeMsgs(t, expectedNetworkBridgeSenderMsgs, actual)
				wg.Done()
			}(c.expectedNetworkBridgeSenderMsgs)

			lenFetchedCandidatesBefore := len(cpvs.fetchedCandidates)

			err := cpvs.processMessage(c.msg)
			if c.errString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.errString)
			}

			if c.deletesFetchCandidate {
				require.Equal(t, lenFetchedCandidatesBefore-1, len(cpvs.fetchedCandidates))
			} else {
				require.Equal(t, lenFetchedCandidatesBefore, len(cpvs.fetchedCandidates))
			}

			wg.Wait()
		})
	}
}

func testCompareNetworkBridgeMsgs(t *testing.T, expected []any, actual []any) {
	for i := 0; i < len(expected); i++ {
		switch expectedMsg := expected[i].(type) {
		case networkbridgemessages.ReportPeer:
			actualMsg, ok := actual[i].(networkbridgemessages.ReportPeer)
			require.True(t, ok)
			require.Equal(t, expectedMsg.PeerID, actualMsg.PeerID)
			require.Equal(t, expectedMsg.ReputationChange.Reason, actualMsg.ReputationChange.Reason)
			require.Equal(t, expectedMsg.ReputationChange.Value, actualMsg.ReputationChange.Value)
		case networkbridgemessages.SendCollationMessage:
			actualMsg, ok := actual[i].(networkbridgemessages.SendCollationMessage)
			require.True(t, ok)
			require.Equal(t, expectedMsg.To, actualMsg.To)
			expectedCollationMsg, err := scale.Marshal(expectedMsg.CollationProtocolMessage)
			require.NoError(t, err)
			actualCollationMsg, err := scale.Marshal(actualMsg.CollationProtocolMessage)
			require.NoError(t, err)
			require.Equal(t, expectedCollationMsg, actualCollationMsg)
		}
	}
}

func TestProcessBackedOverseerMessage(t *testing.T) {
	t.Parallel()

	var testCollatorID parachaintypes.CollatorID
	tempCollatID := common.MustHexToBytes("0x48215b9d322601e5b1a95164cea0dc4626f545f98343d07f1551eb9543c4b147")
	copy(testCollatorID[:], tempCollatID)
	peerID := peer.ID("testPeerID")
	testRelayParent := getDummyHash(5)

	testCases := []struct {
		description                 string
		msg                         any
		canSecond                   bool
		deletesBlockedAdvertisement bool
		blockedAdvertisements       map[string][]blockedAdvertisement
		errString                   string
	}{
		{
			description: "Backed message fails with unknown relay parent",
			msg: collatorprotocolmessages.Backed{
				ParaID:   6,
				ParaHead: common.Hash{},
			},
			canSecond:                   true,
			deletesBlockedAdvertisement: true,
			blockedAdvertisements: map[string][]blockedAdvertisement{
				"para_id:_6,_para_head:_0x0000000000000000000000000000000000000000000000000000000000000000": {
					{
						peerID:               peerID,
						collatorID:           testCollatorID,
						candidateRelayParent: testRelayParent,
						candidateHash:        parachaintypes.CandidateHash{},
					},
				},
				"para_id:_7,_para_head:_0x0000000000000000000000000000000000000000000000000000000000000001": {
					{
						peerID:               peerID,
						collatorID:           testCollatorID,
						candidateRelayParent: testRelayParent,
						candidateHash:        parachaintypes.CandidateHash{},
					},
				},
			},
			errString: ErrRelayParentUnknown.Error(),
		},
		{
			description: "Backed message gets processed successfully when seconding is not allowed",
			msg: collatorprotocolmessages.Backed{
				ParaID:   6,
				ParaHead: common.Hash{},
			},
			canSecond: false,
			blockedAdvertisements: map[string][]blockedAdvertisement{
				"para_id:_6,_para_head:_0x0000000000000000000000000000000000000000000000000000000000000000": {
					{
						peerID:               peerID,
						collatorID:           testCollatorID,
						candidateRelayParent: testRelayParent,
						candidateHash:        parachaintypes.CandidateHash{},
					},
				},
				"para_id:_7,_para_head:_0x0000000000000000000000000000000000000000000000000000000000000001": {
					{
						peerID:               peerID,
						collatorID:           testCollatorID,
						candidateRelayParent: testRelayParent,
						candidateHash:        parachaintypes.CandidateHash{},
					},
				},
			},
			errString: "",
		},
	}
	for _, c := range testCases {
		c := c
		t.Run(c.description, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			overseer := overseer.NewMockableOverseer(t, false)
			overseer.ExpectActions([]func(msg any) bool{
				func(msg any) bool {
					canSecondMessage, ok := msg.(backing.CanSecondMessage)
					if !ok {
						return false
					}
					canSecondMessage.ResponseCh <- c.canSecond

					return true
				},
			}...)

			collationProtocolID := "/6761727661676500000000000000000000000000000000000000000000000000/1/collations/1"

			net := NewMockNetwork(ctrl)
			net.EXPECT().GetRequestResponseProtocol(gomock.Any(), collationFetchingRequestTimeout,
				uint64(collationFetchingMaxResponseSize)).Return(&network.RequestResponseProtocol{})
			cpvs := New(net, protocol.ID(collationProtocolID), overseer.GetSubsystemToOverseerChannel())

			cpvs.BlockedAdvertisements = c.blockedAdvertisements

			overseer.RegisterSubsystem(cpvs)

			err := overseer.Start()
			require.NoError(t, err)

			defer overseer.Stop()

			lenBlackedAdvertisementsBefore := len(cpvs.BlockedAdvertisements)

			err = cpvs.processMessage(c.msg)
			if c.errString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.errString)
			}

			if c.deletesBlockedAdvertisement {
				require.Equal(t, lenBlackedAdvertisementsBefore-1, len(cpvs.BlockedAdvertisements))
			} else {
				require.Equal(t, lenBlackedAdvertisementsBefore, len(cpvs.BlockedAdvertisements))
			}
		})
	}
}

func TestPeerViewChange(t *testing.T) {
	t.Parallel()

	// test that relay parent advertisement gets removed if it went out of implicit view

	cpvs := CollatorProtocolValidatorSide{
		activeLeaves: map[common.Hash]parachaintypes.ProspectiveParachainsMode{},
		perRelayParent: map[common.Hash]PerRelayParent{
			{0x01}: {
				prospectiveParachainMode: parachaintypes.ProspectiveParachainsMode{
					IsEnabled: false,
				},
			},
		},
		peerData: map[peer.ID]PeerData{
			peer.ID("peer1"): {
				// this shows our current view of peer1
				view: parachaintypes.View{
					Heads: []common.Hash{{0x01}},
				},
				state: PeerStateInfo{
					PeerState: Collating,
					CollatingPeerState: CollatingPeerState{
						advertisements: map[common.Hash][]parachaintypes.CandidateHash{
							{0x01}: {},
						},
					},
				},
			},
		},
	}

	msg := networkbridgeevents.PeerViewChange{
		PeerID: peer.ID("peer1"),
		// this shows the new view of peer1, since the new view does not contain relay parent {0x01},
		// we will remove the advertisement for that relay parent
		View: parachaintypes.View{
			Heads: []common.Hash{{0x02}},
		},
	}

	err := cpvs.handleNetworkBridgeEvents(msg)
	require.NoError(t, err)

	// advertisement for relay parent {0x01} should be removed
	_, ok := cpvs.peerData[peer.ID("peer1")].state.CollatingPeerState.advertisements[common.Hash{0x01}]
	require.False(t, ok)
}