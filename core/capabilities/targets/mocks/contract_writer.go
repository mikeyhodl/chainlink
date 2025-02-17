// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	context "context"
	big "math/big"

	mock "github.com/stretchr/testify/mock"

	types "github.com/smartcontractkit/chainlink-common/pkg/types"
)

// ContractWriter is an autogenerated mock type for the ContractWriter type
type ContractWriter struct {
	mock.Mock
}

type ContractWriter_Expecter struct {
	mock *mock.Mock
}

func (_m *ContractWriter) EXPECT() *ContractWriter_Expecter {
	return &ContractWriter_Expecter{mock: &_m.Mock}
}

// Close provides a mock function with no fields
func (_m *ContractWriter) Close() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Close")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContractWriter_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type ContractWriter_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *ContractWriter_Expecter) Close() *ContractWriter_Close_Call {
	return &ContractWriter_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *ContractWriter_Close_Call) Run(run func()) *ContractWriter_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContractWriter_Close_Call) Return(_a0 error) *ContractWriter_Close_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_Close_Call) RunAndReturn(run func() error) *ContractWriter_Close_Call {
	_c.Call.Return(run)
	return _c
}

// GetFeeComponents provides a mock function with given fields: ctx
func (_m *ContractWriter) GetFeeComponents(ctx context.Context) (*types.ChainFeeComponents, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetFeeComponents")
	}

	var r0 *types.ChainFeeComponents
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (*types.ChainFeeComponents, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) *types.ChainFeeComponents); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.ChainFeeComponents)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ContractWriter_GetFeeComponents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFeeComponents'
type ContractWriter_GetFeeComponents_Call struct {
	*mock.Call
}

// GetFeeComponents is a helper method to define mock.On call
//   - ctx context.Context
func (_e *ContractWriter_Expecter) GetFeeComponents(ctx interface{}) *ContractWriter_GetFeeComponents_Call {
	return &ContractWriter_GetFeeComponents_Call{Call: _e.mock.On("GetFeeComponents", ctx)}
}

func (_c *ContractWriter_GetFeeComponents_Call) Run(run func(ctx context.Context)) *ContractWriter_GetFeeComponents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *ContractWriter_GetFeeComponents_Call) Return(_a0 *types.ChainFeeComponents, _a1 error) *ContractWriter_GetFeeComponents_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ContractWriter_GetFeeComponents_Call) RunAndReturn(run func(context.Context) (*types.ChainFeeComponents, error)) *ContractWriter_GetFeeComponents_Call {
	_c.Call.Return(run)
	return _c
}

// GetTransactionStatus provides a mock function with given fields: ctx, transactionID
func (_m *ContractWriter) GetTransactionStatus(ctx context.Context, transactionID string) (types.TransactionStatus, error) {
	ret := _m.Called(ctx, transactionID)

	if len(ret) == 0 {
		panic("no return value specified for GetTransactionStatus")
	}

	var r0 types.TransactionStatus
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (types.TransactionStatus, error)); ok {
		return rf(ctx, transactionID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) types.TransactionStatus); ok {
		r0 = rf(ctx, transactionID)
	} else {
		r0 = ret.Get(0).(types.TransactionStatus)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, transactionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ContractWriter_GetTransactionStatus_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetTransactionStatus'
type ContractWriter_GetTransactionStatus_Call struct {
	*mock.Call
}

// GetTransactionStatus is a helper method to define mock.On call
//   - ctx context.Context
//   - transactionID string
func (_e *ContractWriter_Expecter) GetTransactionStatus(ctx interface{}, transactionID interface{}) *ContractWriter_GetTransactionStatus_Call {
	return &ContractWriter_GetTransactionStatus_Call{Call: _e.mock.On("GetTransactionStatus", ctx, transactionID)}
}

func (_c *ContractWriter_GetTransactionStatus_Call) Run(run func(ctx context.Context, transactionID string)) *ContractWriter_GetTransactionStatus_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *ContractWriter_GetTransactionStatus_Call) Return(_a0 types.TransactionStatus, _a1 error) *ContractWriter_GetTransactionStatus_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ContractWriter_GetTransactionStatus_Call) RunAndReturn(run func(context.Context, string) (types.TransactionStatus, error)) *ContractWriter_GetTransactionStatus_Call {
	_c.Call.Return(run)
	return _c
}

// HealthReport provides a mock function with no fields
func (_m *ContractWriter) HealthReport() map[string]error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for HealthReport")
	}

	var r0 map[string]error
	if rf, ok := ret.Get(0).(func() map[string]error); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]error)
		}
	}

	return r0
}

// ContractWriter_HealthReport_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HealthReport'
type ContractWriter_HealthReport_Call struct {
	*mock.Call
}

// HealthReport is a helper method to define mock.On call
func (_e *ContractWriter_Expecter) HealthReport() *ContractWriter_HealthReport_Call {
	return &ContractWriter_HealthReport_Call{Call: _e.mock.On("HealthReport")}
}

func (_c *ContractWriter_HealthReport_Call) Run(run func()) *ContractWriter_HealthReport_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContractWriter_HealthReport_Call) Return(_a0 map[string]error) *ContractWriter_HealthReport_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_HealthReport_Call) RunAndReturn(run func() map[string]error) *ContractWriter_HealthReport_Call {
	_c.Call.Return(run)
	return _c
}

// Name provides a mock function with no fields
func (_m *ContractWriter) Name() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Name")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// ContractWriter_Name_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Name'
type ContractWriter_Name_Call struct {
	*mock.Call
}

// Name is a helper method to define mock.On call
func (_e *ContractWriter_Expecter) Name() *ContractWriter_Name_Call {
	return &ContractWriter_Name_Call{Call: _e.mock.On("Name")}
}

func (_c *ContractWriter_Name_Call) Run(run func()) *ContractWriter_Name_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContractWriter_Name_Call) Return(_a0 string) *ContractWriter_Name_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_Name_Call) RunAndReturn(run func() string) *ContractWriter_Name_Call {
	_c.Call.Return(run)
	return _c
}

// Ready provides a mock function with no fields
func (_m *ContractWriter) Ready() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Ready")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContractWriter_Ready_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Ready'
type ContractWriter_Ready_Call struct {
	*mock.Call
}

// Ready is a helper method to define mock.On call
func (_e *ContractWriter_Expecter) Ready() *ContractWriter_Ready_Call {
	return &ContractWriter_Ready_Call{Call: _e.mock.On("Ready")}
}

func (_c *ContractWriter_Ready_Call) Run(run func()) *ContractWriter_Ready_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContractWriter_Ready_Call) Return(_a0 error) *ContractWriter_Ready_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_Ready_Call) RunAndReturn(run func() error) *ContractWriter_Ready_Call {
	_c.Call.Return(run)
	return _c
}

// Start provides a mock function with given fields: _a0
func (_m *ContractWriter) Start(_a0 context.Context) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Start")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContractWriter_Start_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Start'
type ContractWriter_Start_Call struct {
	*mock.Call
}

// Start is a helper method to define mock.On call
//   - _a0 context.Context
func (_e *ContractWriter_Expecter) Start(_a0 interface{}) *ContractWriter_Start_Call {
	return &ContractWriter_Start_Call{Call: _e.mock.On("Start", _a0)}
}

func (_c *ContractWriter_Start_Call) Run(run func(_a0 context.Context)) *ContractWriter_Start_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *ContractWriter_Start_Call) Return(_a0 error) *ContractWriter_Start_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_Start_Call) RunAndReturn(run func(context.Context) error) *ContractWriter_Start_Call {
	_c.Call.Return(run)
	return _c
}

// SubmitTransaction provides a mock function with given fields: ctx, contractName, method, args, transactionID, toAddress, meta, value
func (_m *ContractWriter) SubmitTransaction(ctx context.Context, contractName string, method string, args interface{}, transactionID string, toAddress string, meta *types.TxMeta, value *big.Int) error {
	ret := _m.Called(ctx, contractName, method, args, transactionID, toAddress, meta, value)

	if len(ret) == 0 {
		panic("no return value specified for SubmitTransaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, interface{}, string, string, *types.TxMeta, *big.Int) error); ok {
		r0 = rf(ctx, contractName, method, args, transactionID, toAddress, meta, value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContractWriter_SubmitTransaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SubmitTransaction'
type ContractWriter_SubmitTransaction_Call struct {
	*mock.Call
}

// SubmitTransaction is a helper method to define mock.On call
//   - ctx context.Context
//   - contractName string
//   - method string
//   - args interface{}
//   - transactionID string
//   - toAddress string
//   - meta *types.TxMeta
//   - value *big.Int
func (_e *ContractWriter_Expecter) SubmitTransaction(ctx interface{}, contractName interface{}, method interface{}, args interface{}, transactionID interface{}, toAddress interface{}, meta interface{}, value interface{}) *ContractWriter_SubmitTransaction_Call {
	return &ContractWriter_SubmitTransaction_Call{Call: _e.mock.On("SubmitTransaction", ctx, contractName, method, args, transactionID, toAddress, meta, value)}
}

func (_c *ContractWriter_SubmitTransaction_Call) Run(run func(ctx context.Context, contractName string, method string, args interface{}, transactionID string, toAddress string, meta *types.TxMeta, value *big.Int)) *ContractWriter_SubmitTransaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(interface{}), args[4].(string), args[5].(string), args[6].(*types.TxMeta), args[7].(*big.Int))
	})
	return _c
}

func (_c *ContractWriter_SubmitTransaction_Call) Return(_a0 error) *ContractWriter_SubmitTransaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContractWriter_SubmitTransaction_Call) RunAndReturn(run func(context.Context, string, string, interface{}, string, string, *types.TxMeta, *big.Int) error) *ContractWriter_SubmitTransaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewContractWriter creates a new instance of ContractWriter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewContractWriter(t interface {
	mock.TestingT
	Cleanup(func())
}) *ContractWriter {
	mock := &ContractWriter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
