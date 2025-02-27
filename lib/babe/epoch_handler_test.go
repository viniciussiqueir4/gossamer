// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package babe

import (
	"testing"
	"time"

	"github.com/ChainSafe/gossamer/dot/types"
	"github.com/ChainSafe/gossamer/lib/crypto/sr25519"
	"github.com/ChainSafe/gossamer/pkg/scale"

	"github.com/stretchr/testify/require"
)

func TestNewEpochHandler(t *testing.T) {
	testHandleSlotFunc := func(epoch uint64, slot Slot, authorityIndex uint32,
		preRuntimeDigest *types.PreRuntimeDigest,
	) error {
		return nil
	}

	epochData := &epochData{
		threshold: scale.MaxUint128,
	}

	sd, err := time.ParseDuration("6s")
	require.NoError(t, err)

	testConstants := constants{
		slotDuration: sd,
		epochLength:  200,
	}

	keypair := keyring.Alice().(*sr25519.Keypair)

	startSlot := uint64(9999)
	epochDescriptor := &epochDescriptor{
		data:      epochData,
		startSlot: startSlot,
		endSlot:   startSlot + testConstants.epochLength,
		epoch:     1,
	}

	epochHandler, err := newEpochHandler(epochDescriptor, testConstants, testHandleSlotFunc, keypair)
	require.NoError(t, err)
	require.Equal(t, 200, len(epochHandler.slotToPreRuntimeDigest))
	require.Equal(t, uint64(1), epochHandler.descriptor.epoch)
	require.Equal(t, uint64(9999), epochHandler.descriptor.startSlot)
	require.Equal(t, testConstants, epochHandler.constants)
	require.Equal(t, epochData, epochHandler.descriptor.data)
	require.NotNil(t, epochHandler.handleSlot)
}
