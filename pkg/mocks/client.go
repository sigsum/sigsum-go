// Code generated by MockGen. DO NOT EDIT.
// Source: sigsum.org/sigsum-go/pkg/client (interfaces: Log)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	requests "sigsum.org/sigsum-go/pkg/requests"
	types "sigsum.org/sigsum-go/pkg/types"
)

// MockLogClient is a mock of Log interface.
type MockLogClient struct {
	ctrl     *gomock.Controller
	recorder *MockLogClientMockRecorder
}

// MockLogClientMockRecorder is the mock recorder for MockLogClient.
type MockLogClientMockRecorder struct {
	mock *MockLogClient
}

// NewMockLogClient creates a new mock instance.
func NewMockLogClient(ctrl *gomock.Controller) *MockLogClient {
	mock := &MockLogClient{ctrl: ctrl}
	mock.recorder = &MockLogClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLogClient) EXPECT() *MockLogClientMockRecorder {
	return m.recorder
}

// AddLeaf mocks base method.
func (m *MockLogClient) AddLeaf(arg0 context.Context, arg1 requests.Leaf, arg2 *string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddLeaf", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddLeaf indicates an expected call of AddLeaf.
func (mr *MockLogClientMockRecorder) AddLeaf(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddLeaf", reflect.TypeOf((*MockLogClient)(nil).AddLeaf), arg0, arg1, arg2)
}

// GetConsistencyProof mocks base method.
func (m *MockLogClient) GetConsistencyProof(arg0 context.Context, arg1 requests.ConsistencyProof) (types.ConsistencyProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConsistencyProof", arg0, arg1)
	ret0, _ := ret[0].(types.ConsistencyProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConsistencyProof indicates an expected call of GetConsistencyProof.
func (mr *MockLogClientMockRecorder) GetConsistencyProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConsistencyProof", reflect.TypeOf((*MockLogClient)(nil).GetConsistencyProof), arg0, arg1)
}

// GetInclusionProof mocks base method.
func (m *MockLogClient) GetInclusionProof(arg0 context.Context, arg1 requests.InclusionProof) (types.InclusionProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInclusionProof", arg0, arg1)
	ret0, _ := ret[0].(types.InclusionProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInclusionProof indicates an expected call of GetInclusionProof.
func (mr *MockLogClientMockRecorder) GetInclusionProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInclusionProof", reflect.TypeOf((*MockLogClient)(nil).GetInclusionProof), arg0, arg1)
}

// GetLeaves mocks base method.
func (m *MockLogClient) GetLeaves(arg0 context.Context, arg1 requests.Leaves) ([]types.Leaf, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLeaves", arg0, arg1)
	ret0, _ := ret[0].([]types.Leaf)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLeaves indicates an expected call of GetLeaves.
func (mr *MockLogClientMockRecorder) GetLeaves(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLeaves", reflect.TypeOf((*MockLogClient)(nil).GetLeaves), arg0, arg1)
}

// GetTreeHead mocks base method.
func (m *MockLogClient) GetTreeHead(arg0 context.Context) (types.CosignedTreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTreeHead", arg0)
	ret0, _ := ret[0].(types.CosignedTreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTreeHead indicates an expected call of GetTreeHead.
func (mr *MockLogClientMockRecorder) GetTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTreeHead", reflect.TypeOf((*MockLogClient)(nil).GetTreeHead), arg0)
}
