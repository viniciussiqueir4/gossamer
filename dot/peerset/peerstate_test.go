// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package peerset

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestFullSlotIn(t *testing.T) {
	t.Parallel()

	state := newTestPeerState(t, 1, 1)

	// initially peer1 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer1))
	// insertPeer peer1
	state.insertPeer(0, peer1)
	// peer1 state will change from unknownPeer to notConnectedPeer, once we tried to insertPeer it.
	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer1))
	// try to make peer1 as an incoming connection.
	err := state.tryAcceptIncoming(0, peer1)
	require.NoError(t, err)

	// peer1 is connected
	require.Equal(t, connectedPeer, state.peerStatus(0, peer1))

	// initially peer2 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer2))
	// insertPeer peer2
	state.insertPeer(0, peer2)
	// try to make peer2 as an incoming connection.
	err = state.tryAcceptIncoming(0, peer2)
	// peer2 will not be accepted as incoming connection, as we only have one incoming connection slot ingoing peerState.
	require.Error(t, err)
}

func TestNoSlotNodeDoesntOccupySlot(t *testing.T) {
	t.Parallel()

	state := newTestPeerState(t, 1, 1)
	state.nodes[peer1] = newNode(1)

	// peer1 will not occupy any slot.
	err := state.addNoSlotNode(0, peer1)
	require.NoError(t, err)

	// initially peer1 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer1))
	// insertPeer peer1
	state.insertPeer(0, peer1)
	// peer1 will become an incoming connection.
	err = state.tryAcceptIncoming(0, peer1)
	require.NoError(t, err)
	// peer1 is connected
	require.Equal(t, connectedPeer, state.peerStatus(0, peer1))

	// peer1 is connected, but the slot is still not occupied.
	require.Equal(t, uint32(0), state.sets[0].numIn)

	// initially peer2 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer2))
	// insertPeer peer2
	state.insertPeer(0, peer2)
	// peer2 state will change from unknownPeer to notConnectedPeer, once we tried to insertPeer it.
	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer2))

	// try to accept peer2 as an incoming connection.
	err = state.tryAcceptIncoming(0, peer2)
	require.NoError(t, err)

	// peer2 is connected
	require.Equal(t, connectedPeer, state.peerStatus(0, peer2))

	// peer2 is connected, but the slot is still not occupied.
	require.Equal(t, uint32(1), state.sets[0].numIn)
}

func TestDisconnectingFreeSlot(t *testing.T) {
	t.Parallel()

	state := newTestPeerState(t, 1, 1)

	// initially peer1 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer1))
	// insertPeer peer1
	state.insertPeer(0, peer1)
	err := state.tryAcceptIncoming(0, peer1) // try to make peer1 as an incoming connection.
	require.NoError(t, err)
	// peer1 is connected
	require.Equal(t, connectedPeer, state.peerStatus(0, peer1))

	// initially peer2 state will be unknownPeer.
	require.Equal(t, unknownPeer, state.peerStatus(0, peer2))
	// insertPeer peer2
	state.insertPeer(0, peer2)
	// peer2 state will change from unknownPeer to notConnectedPeer, once we tried to insertPeer it.
	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer2))
	// try to make peer2 as an incoming connection.
	err = state.tryAcceptIncoming(0, peer2)
	// peer2 will not be accepted as incoming connection,
	// as we only have one incoming connection slot ingoing peerState.
	require.Error(t, err)

	// disconnect peer1
	err = state.disconnect(0, peer1)
	require.NoError(t, err)

	// peer2 will be accepted as incoming connection, as peer1 is disconnected.
	err = state.tryAcceptIncoming(0, peer2)
	require.NoError(t, err)
}

func TestDisconnectNoSlotDoesntPanic(t *testing.T) {
	t.Parallel()

	state := newTestPeerState(t, 1, 1)

	state.nodes[peer1] = newNode(1)
	err := state.addNoSlotNode(0, peer1)
	require.NoError(t, err)

	require.Equal(t, unknownPeer, state.peerStatus(0, peer1))

	state.insertPeer(0, peer1)
	err = state.tryOutgoing(0, peer1)
	require.NoError(t, err)

	require.Equal(t, connectedPeer, state.peerStatus(0, peer1))

	err = state.disconnect(0, peer1)
	require.NoError(t, err)

	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer1))
}

func TestHighestNotConnectedPeer(t *testing.T) {
	t.Parallel()

	state := newTestPeerState(t, 25, 25)
	emptyPeerID := peer.ID("")

	require.Equal(t, emptyPeerID, state.highestNotConnectedPeer(0))

	require.Equal(t, unknownPeer, state.peerStatus(0, peer1))

	state.insertPeer(0, peer1)
	n, err := state.getNode(peer1)
	require.NoError(t, err)

	n.reputation = 50
	state.nodes[peer1] = n

	require.Equal(t, Reputation(50), state.nodes[peer1].reputation)

	require.Equal(t, unknownPeer, state.peerStatus(0, peer2))

	state.insertPeer(0, peer2)
	n, err = state.getNode(peer2)
	require.NoError(t, err)
	n.reputation = 25
	state.nodes[peer2] = n

	// peer1 still has the highest reputation
	require.Equal(t, peer1, state.highestNotConnectedPeer(0))
	require.Equal(t, Reputation(25), state.nodes[peer2].reputation)

	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer2))

	n, err = state.getNode(peer2)
	require.NoError(t, err)

	n.reputation = 75
	state.nodes[peer2] = n

	require.Equal(t, peer2, state.highestNotConnectedPeer(0))
	require.Equal(t, Reputation(75), state.nodes[peer2].reputation)

	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer2))
	err = state.tryAcceptIncoming(0, peer2)
	require.NoError(t, err)

	require.Equal(t, peer1, state.highestNotConnectedPeer(0))

	require.Equal(t, connectedPeer, state.peerStatus(0, peer2))
	err = state.disconnect(0, peer2)
	require.NoError(t, err)

	require.Equal(t, notConnectedPeer, state.peerStatus(0, peer1))
	n, err = state.getNode(peer1)
	require.NoError(t, err)
	n.reputation = 100
	state.nodes[peer1] = n

	require.Equal(t, peer1, state.highestNotConnectedPeer(0))
}
