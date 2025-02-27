// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/internal/pprof (interfaces: Runner)
//
// Generated by this command:
//
//	mockgen -destination=runner_mock_test.go -package pprof . Runner
//

// Package pprof is a generated GoMock package.
package pprof

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockRunner is a mock of Runner interface.
type MockRunner struct {
	ctrl     *gomock.Controller
	recorder *MockRunnerMockRecorder
}

// MockRunnerMockRecorder is the mock recorder for MockRunner.
type MockRunnerMockRecorder struct {
	mock *MockRunner
}

// NewMockRunner creates a new mock instance.
func NewMockRunner(ctrl *gomock.Controller) *MockRunner {
	mock := &MockRunner{ctrl: ctrl}
	mock.recorder = &MockRunnerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRunner) EXPECT() *MockRunnerMockRecorder {
	return m.recorder
}

// Run mocks base method.
func (m *MockRunner) Run(arg0 context.Context, arg1 chan<- struct{}, arg2 chan<- error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Run", arg0, arg1, arg2)
}

// Run indicates an expected call of Run.
func (mr *MockRunnerMockRecorder) Run(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockRunner)(nil).Run), arg0, arg1, arg2)
}
