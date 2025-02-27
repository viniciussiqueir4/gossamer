// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package network

import (
	"github.com/ChainSafe/gossamer/dot/network/messages"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// handleSyncStream handles streams with the <protocol-id>/sync/2 protocol ID
func (s *Service) handleSyncStream(stream libp2pnetwork.Stream) {
	if stream == nil {
		return
	}

	s.readStream(stream, decodeSyncMessage, s.handleSyncMessage, MaxBlockResponseSize)
}

func decodeSyncMessage(in []byte, _ peer.ID, _ bool) (messages.P2PMessage, error) {
	msg := new(messages.BlockRequestMessage)
	err := msg.Decode(in)
	return msg, err
}

// handleSyncMessage handles inbound sync streams
// the only messages we should receive over an inbound stream are BlockRequestMessages, so we only need to handle those
func (s *Service) handleSyncMessage(stream libp2pnetwork.Stream, msg messages.P2PMessage) error {
	if msg == nil {
		return nil
	}

	defer func() {
		err := stream.Close()
		if err != nil && err.Error() != ErrStreamReset.Error() {
			logger.Warnf("failed to close stream: %s", err)
		}
	}()

	if req, ok := msg.(*messages.BlockRequestMessage); ok {
		resp, err := s.syncer.CreateBlockResponse(stream.Conn().RemotePeer(), req)
		if err != nil {
			logger.Debugf("cannot create response for request: %s", err)
			return nil
		}

		if err = s.host.writeToStream(stream, resp); err != nil {
			logger.Debugf("failed to send BlockResponse message to peer %s: %s", stream.Conn().RemotePeer(), err)
			return err
		}
	}

	return nil
}
