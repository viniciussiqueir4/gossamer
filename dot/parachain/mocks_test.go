// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/parachain (interfaces: PoVRequestor)

// Package parachain is a generated GoMock package.
package parachain

import (
	reflect "reflect"

	common "github.com/ChainSafe/gossamer/lib/common"
	gomock "go.uber.org/mock/gomock"
)

// MockPoVRequestor is a mock of PoVRequestor interface.
type MockPoVRequestor struct {
	ctrl     *gomock.Controller
	recorder *MockPoVRequestorMockRecorder
}

// MockPoVRequestorMockRecorder is the mock recorder for MockPoVRequestor.
type MockPoVRequestorMockRecorder struct {
	mock *MockPoVRequestor
}

// NewMockPoVRequestor creates a new mock instance.
func NewMockPoVRequestor(ctrl *gomock.Controller) *MockPoVRequestor {
	mock := &MockPoVRequestor{ctrl: ctrl}
	mock.recorder = &MockPoVRequestorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPoVRequestor) EXPECT() *MockPoVRequestorMockRecorder {
	return m.recorder
}

// RequestPoV mocks base method.
func (m *MockPoVRequestor) RequestPoV(arg0 common.Hash) PoV {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestPoV", arg0)
	ret0, _ := ret[0].(PoV)
	return ret0
}

// RequestPoV indicates an expected call of RequestPoV.
func (mr *MockPoVRequestorMockRecorder) RequestPoV(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestPoV", reflect.TypeOf((*MockPoVRequestor)(nil).RequestPoV), arg0)
}