// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package parachain

import (
	"fmt"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	"github.com/ChainSafe/gossamer/pkg/scale"
)

// PoVFetchingRequest represents a request to fetch the advertised collation at the relay-parent.
type PoVFetchingRequest struct {
	// Hash of the candidate for which we want to retrieve a Proof-of-Validity (PoV).
	CandidateHash parachaintypes.CandidateHash
}

// Encode returns the SCALE encoding of the PoVFetchingRequest
func (p PoVFetchingRequest) Encode() ([]byte, error) {
	return scale.Marshal(p)
}

type PoVFetchingResponseValues interface {
	parachaintypes.PoV | parachaintypes.NoSuchPoV
}

// PoVFetchingResponse represents the possible responses to a PoVFetchingRequest.
type PoVFetchingResponse struct {
	inner any
}

func setPoVFetchingResponse[Value PoVFetchingResponseValues](mvdt *PoVFetchingResponse, value Value) {
	mvdt.inner = value
}

func (mvdt *PoVFetchingResponse) SetValue(value any) (err error) {
	switch value := value.(type) {
	case parachaintypes.PoV:
		setPoVFetchingResponse(mvdt, value)
		return

	case parachaintypes.NoSuchPoV:
		setPoVFetchingResponse(mvdt, value)
		return

	default:
		return fmt.Errorf("unsupported type")
	}
}

func (mvdt PoVFetchingResponse) IndexValue() (index uint, value any, err error) {
	switch mvdt.inner.(type) {
	case parachaintypes.PoV:
		return 0, mvdt.inner, nil

	case parachaintypes.NoSuchPoV:
		return 1, mvdt.inner, nil

	}
	return 0, nil, scale.ErrUnsupportedVaryingDataTypeValue
}

func (mvdt PoVFetchingResponse) Value() (value any, err error) {
	_, value, err = mvdt.IndexValue()
	return
}

func (mvdt PoVFetchingResponse) ValueAt(index uint) (value any, err error) {
	switch index {
	case 0:
		return *new(parachaintypes.PoV), nil

	case 1:
		return *new(parachaintypes.NoSuchPoV), nil

	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}

// NewPoVFetchingResponse returns a new PoV fetching response varying data type
func NewPoVFetchingResponse() PoVFetchingResponse {
	return PoVFetchingResponse{}
}

// Encode returns the SCALE encoding of the PoVFetchingResponse
func (p *PoVFetchingResponse) Encode() ([]byte, error) {
	return scale.Marshal(*p)
}

// Decode returns the SCALE decoding of the PoVFetchingResponse.
func (p *PoVFetchingResponse) Decode(in []byte) (err error) {
	return scale.Unmarshal(in, p)
}

// String formats a PoVFetchingResponse as a string
func (p *PoVFetchingResponse) String() string {
	if p == nil {
		return "PoVFetchingResponse=nil"
	}

	v, _ := p.Value()
	pov, ok := v.(parachaintypes.PoV)
	if !ok {
		return "PoVFetchingResponse=NoSuchPoV"
	}
	return fmt.Sprintf("PoVFetchingResponse PoV=%+v", pov)
}