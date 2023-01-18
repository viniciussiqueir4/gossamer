// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/state (interfaces: Telemetry,BlockStateDatabase,Observer)

// Package state is a generated GoMock package.
package state

import (
	json "encoding/json"
	reflect "reflect"

	chaindb "github.com/ChainSafe/chaindb"
	gomock "github.com/golang/mock/gomock"
)

// MockTelemetry is a mock of Telemetry interface.
type MockTelemetry struct {
	ctrl     *gomock.Controller
	recorder *MockTelemetryMockRecorder
}

// MockTelemetryMockRecorder is the mock recorder for MockTelemetry.
type MockTelemetryMockRecorder struct {
	mock *MockTelemetry
}

// NewMockTelemetry creates a new mock instance.
func NewMockTelemetry(ctrl *gomock.Controller) *MockTelemetry {
	mock := &MockTelemetry{ctrl: ctrl}
	mock.recorder = &MockTelemetryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTelemetry) EXPECT() *MockTelemetryMockRecorder {
	return m.recorder
}

// SendMessage mocks base method.
func (m *MockTelemetry) SendMessage(arg0 json.Marshaler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SendMessage", arg0)
}

// SendMessage indicates an expected call of SendMessage.
func (mr *MockTelemetryMockRecorder) SendMessage(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMessage", reflect.TypeOf((*MockTelemetry)(nil).SendMessage), arg0)
}

// MockBlockStateDatabase is a mock of BlockStateDatabase interface.
type MockBlockStateDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockBlockStateDatabaseMockRecorder
}

// MockBlockStateDatabaseMockRecorder is the mock recorder for MockBlockStateDatabase.
type MockBlockStateDatabaseMockRecorder struct {
	mock *MockBlockStateDatabase
}

// NewMockBlockStateDatabase creates a new mock instance.
func NewMockBlockStateDatabase(ctrl *gomock.Controller) *MockBlockStateDatabase {
	mock := &MockBlockStateDatabase{ctrl: ctrl}
	mock.recorder = &MockBlockStateDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlockStateDatabase) EXPECT() *MockBlockStateDatabaseMockRecorder {
	return m.recorder
}

// Del mocks base method.
func (m *MockBlockStateDatabase) Del(arg0 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Del", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Del indicates an expected call of Del.
func (mr *MockBlockStateDatabaseMockRecorder) Del(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockBlockStateDatabase)(nil).Del), arg0)
}

// Get mocks base method.
func (m *MockBlockStateDatabase) Get(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockBlockStateDatabaseMockRecorder) Get(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockBlockStateDatabase)(nil).Get), arg0)
}

// Has mocks base method.
func (m *MockBlockStateDatabase) Has(arg0 []byte) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Has", arg0)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Has indicates an expected call of Has.
func (mr *MockBlockStateDatabaseMockRecorder) Has(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Has", reflect.TypeOf((*MockBlockStateDatabase)(nil).Has), arg0)
}

// NewBatch mocks base method.
func (m *MockBlockStateDatabase) NewBatch() chaindb.Batch {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewBatch")
	ret0, _ := ret[0].(chaindb.Batch)
	return ret0
}

// NewBatch indicates an expected call of NewBatch.
func (mr *MockBlockStateDatabaseMockRecorder) NewBatch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewBatch", reflect.TypeOf((*MockBlockStateDatabase)(nil).NewBatch))
}

// Put mocks base method.
func (m *MockBlockStateDatabase) Put(arg0, arg1 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Put", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockBlockStateDatabaseMockRecorder) Put(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockBlockStateDatabase)(nil).Put), arg0, arg1)
}

// MockObserver is a mock of Observer interface.
type MockObserver struct {
	ctrl     *gomock.Controller
	recorder *MockObserverMockRecorder
}

// MockObserverMockRecorder is the mock recorder for MockObserver.
type MockObserverMockRecorder struct {
	mock *MockObserver
}

// NewMockObserver creates a new mock instance.
func NewMockObserver(ctrl *gomock.Controller) *MockObserver {
	mock := &MockObserver{ctrl: ctrl}
	mock.recorder = &MockObserverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockObserver) EXPECT() *MockObserverMockRecorder {
	return m.recorder
}

// GetFilter mocks base method.
func (m *MockObserver) GetFilter() map[string][]byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilter")
	ret0, _ := ret[0].(map[string][]byte)
	return ret0
}

// GetFilter indicates an expected call of GetFilter.
func (mr *MockObserverMockRecorder) GetFilter() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilter", reflect.TypeOf((*MockObserver)(nil).GetFilter))
}

// GetID mocks base method.
func (m *MockObserver) GetID() uint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(uint)
	return ret0
}

// GetID indicates an expected call of GetID.
func (mr *MockObserverMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockObserver)(nil).GetID))
}

// Update mocks base method.
func (m *MockObserver) Update(arg0 *SubscriptionResult) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Update", arg0)
}

// Update indicates an expected call of Update.
func (mr *MockObserverMockRecorder) Update(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockObserver)(nil).Update), arg0)
}