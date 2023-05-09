// Code generated by MockGen. DO NOT EDIT.
// Source: sigsum.org/sigsum-go/pkg/client (interfaces: Log,Secondary,Witness)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	requests "sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
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
func (m *MockLogClient) AddLeaf(arg0 context.Context, arg1 requests.Leaf, arg2 *token.SubmitToken) (bool, error) {
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

// MockSecondaryClient is a mock of Secondary interface.
type MockSecondaryClient struct {
	ctrl     *gomock.Controller
	recorder *MockSecondaryClientMockRecorder
}

// MockSecondaryClientMockRecorder is the mock recorder for MockSecondaryClient.
type MockSecondaryClientMockRecorder struct {
	mock *MockSecondaryClient
}

// NewMockSecondaryClient creates a new mock instance.
func NewMockSecondaryClient(ctrl *gomock.Controller) *MockSecondaryClient {
	mock := &MockSecondaryClient{ctrl: ctrl}
	mock.recorder = &MockSecondaryClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecondaryClient) EXPECT() *MockSecondaryClientMockRecorder {
	return m.recorder
}

// GetSecondaryTreeHead mocks base method.
func (m *MockSecondaryClient) GetSecondaryTreeHead(arg0 context.Context) (types.SignedTreeHead, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecondaryTreeHead", arg0)
	ret0, _ := ret[0].(types.SignedTreeHead)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecondaryTreeHead indicates an expected call of GetSecondaryTreeHead.
func (mr *MockSecondaryClientMockRecorder) GetSecondaryTreeHead(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecondaryTreeHead", reflect.TypeOf((*MockSecondaryClient)(nil).GetSecondaryTreeHead), arg0)
}

// MockWitnessClient is a mock of Witness interface.
type MockWitnessClient struct {
	ctrl     *gomock.Controller
	recorder *MockWitnessClientMockRecorder
}

// MockWitnessClientMockRecorder is the mock recorder for MockWitnessClient.
type MockWitnessClientMockRecorder struct {
	mock *MockWitnessClient
}

// NewMockWitnessClient creates a new mock instance.
func NewMockWitnessClient(ctrl *gomock.Controller) *MockWitnessClient {
	mock := &MockWitnessClient{ctrl: ctrl}
	mock.recorder = &MockWitnessClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWitnessClient) EXPECT() *MockWitnessClientMockRecorder {
	return m.recorder
}

// AddTreeHead mocks base method.
func (m *MockWitnessClient) AddTreeHead(arg0 context.Context, arg1 requests.AddTreeHead) (types.Cosignature, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddTreeHead", arg0, arg1)
	ret0, _ := ret[0].(types.Cosignature)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddTreeHead indicates an expected call of AddTreeHead.
func (mr *MockWitnessClientMockRecorder) AddTreeHead(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddTreeHead", reflect.TypeOf((*MockWitnessClient)(nil).AddTreeHead), arg0, arg1)
}

// GetTreeSize mocks base method.
func (m *MockWitnessClient) GetTreeSize(arg0 context.Context, arg1 requests.GetTreeSize) (uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTreeSize", arg0, arg1)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTreeSize indicates an expected call of GetTreeSize.
func (mr *MockWitnessClientMockRecorder) GetTreeSize(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTreeSize", reflect.TypeOf((*MockWitnessClient)(nil).GetTreeSize), arg0, arg1)
}
