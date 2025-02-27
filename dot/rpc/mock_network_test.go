// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/core (interfaces: Network)
//
// Generated by this command:
//
//	mockgen -destination=mock_network_test.go -package rpc github.com/ChainSafe/gossamer/dot/core Network
//

// Package rpc is a generated GoMock package.
package rpc

import (
	reflect "reflect"

	network "github.com/ChainSafe/gossamer/dot/network"
	peerset "github.com/ChainSafe/gossamer/dot/peerset"
	peer "github.com/libp2p/go-libp2p/core/peer"
	gomock "go.uber.org/mock/gomock"
)

// MockNetwork is a mock of Network interface.
type MockNetwork struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkMockRecorder
}

// MockNetworkMockRecorder is the mock recorder for MockNetwork.
type MockNetworkMockRecorder struct {
	mock *MockNetwork
}

// NewMockNetwork creates a new mock instance.
func NewMockNetwork(ctrl *gomock.Controller) *MockNetwork {
	mock := &MockNetwork{ctrl: ctrl}
	mock.recorder = &MockNetworkMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork) EXPECT() *MockNetworkMockRecorder {
	return m.recorder
}

// GossipMessage mocks base method.
func (m *MockNetwork) GossipMessage(arg0 network.NotificationsMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GossipMessage", arg0)
}

// GossipMessage indicates an expected call of GossipMessage.
func (mr *MockNetworkMockRecorder) GossipMessage(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GossipMessage", reflect.TypeOf((*MockNetwork)(nil).GossipMessage), arg0)
}

// IsSynced mocks base method.
func (m *MockNetwork) IsSynced() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSynced")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsSynced indicates an expected call of IsSynced.
func (mr *MockNetworkMockRecorder) IsSynced() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSynced", reflect.TypeOf((*MockNetwork)(nil).IsSynced))
}

// ReportPeer mocks base method.
func (m *MockNetwork) ReportPeer(arg0 peerset.ReputationChange, arg1 peer.ID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportPeer", arg0, arg1)
}

// ReportPeer indicates an expected call of ReportPeer.
func (mr *MockNetworkMockRecorder) ReportPeer(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportPeer", reflect.TypeOf((*MockNetwork)(nil).ReportPeer), arg0, arg1)
}
