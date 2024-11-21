package executable_test

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commoncap "github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/services/servicetest"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-common/pkg/values"
	"github.com/smartcontractkit/chainlink/v2/core/capabilities/remote/executable"
	remotetypes "github.com/smartcontractkit/chainlink/v2/core/capabilities/remote/types"
	"github.com/smartcontractkit/chainlink/v2/core/capabilities/transmission"
	"github.com/smartcontractkit/chainlink/v2/core/internal/testutils"
	"github.com/smartcontractkit/chainlink/v2/core/logger"
	p2ptypes "github.com/smartcontractkit/chainlink/v2/core/services/p2p/types"
)

func Test_RemoteExecutableCapability_TransmissionSchedules(t *testing.T) {
	ctx := testutils.Context(t)

	responseTest := func(t *testing.T, response commoncap.CapabilityResponse, responseError error) {
		require.NoError(t, responseError)
		mp, err := response.Value.Unwrap()
		require.NoError(t, err)
		assert.Equal(t, "aValue1", mp.(map[string]any)["response"].(string))
	}

	transmissionSchedule, err := values.NewMap(map[string]any{
		"schedule":   transmission.Schedule_OneAtATime,
		"deltaStage": "10ms",
	})
	require.NoError(t, err)

	timeOut := 10 * time.Minute

	capability := &TestCapability{}

	method := func(ctx context.Context, caller commoncap.ExecutableCapability) {
		executeCapability(ctx, t, caller, transmissionSchedule, responseTest)
	}
	testRemoteExecutableCapability(ctx, t, capability, 10, 9, timeOut, 10, 9, timeOut, method)

	transmissionSchedule, err = values.NewMap(map[string]any{
		"schedule":   transmission.Schedule_AllAtOnce,
		"deltaStage": "10ms",
	})
	require.NoError(t, err)
	method = func(ctx context.Context, caller commoncap.ExecutableCapability) {
		executeCapability(ctx, t, caller, transmissionSchedule, responseTest)
	}

	testRemoteExecutableCapability(ctx, t, capability, 10, 9, timeOut, 10, 9, timeOut, method)
}

func Test_RemoteExecutionCapability_DonTopologies(t *testing.T) {
	ctx := testutils.Context(t)

	responseTest := func(t *testing.T, response commoncap.CapabilityResponse, responseError error) {
		require.NoError(t, responseError)
		mp, err := response.Value.Unwrap()
		require.NoError(t, err)
		assert.Equal(t, "aValue1", mp.(map[string]any)["response"].(string))
	}

	transmissionSchedule, err := values.NewMap(map[string]any{
		"schedule":   transmission.Schedule_OneAtATime,
		"deltaStage": "10ms",
	})
	require.NoError(t, err)

	timeOut := 10 * time.Minute

	capability := &TestCapability{}

	var methods []func(ctx context.Context, caller commoncap.ExecutableCapability)

	methods = append(methods, func(ctx context.Context, caller commoncap.ExecutableCapability) {
		executeCapability(ctx, t, caller, transmissionSchedule, responseTest)
	})

	methods = append(methods, func(ctx context.Context, caller commoncap.ExecutableCapability) {
		registerWorkflow(ctx, t, caller, transmissionSchedule, func(t *testing.T, responseError error) {
			require.NoError(t, responseError)
		})
	})

	methods = append(methods, func(ctx context.Context, caller commoncap.ExecutableCapability) {
		unregisterWorkflow(ctx, t, caller, transmissionSchedule, func(t *testing.T, responseError error) {
			require.NoError(t, responseError)
		})
	})

	for _, method := range methods {
		// Test scenarios where the number of submissions is greater than or equal to F + 1
		testRemoteExecutableCapability(ctx, t, capability, 1, 0, timeOut, 1, 0, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 4, 3, timeOut, 1, 0, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 10, 3, timeOut, 1, 0, timeOut, method)

		testRemoteExecutableCapability(ctx, t, capability, 1, 0, timeOut, 1, 0, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 1, 0, timeOut, 4, 3, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 1, 0, timeOut, 10, 3, timeOut, method)

		testRemoteExecutableCapability(ctx, t, capability, 4, 3, timeOut, 4, 3, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 10, 3, timeOut, 10, 3, timeOut, method)
		testRemoteExecutableCapability(ctx, t, capability, 10, 9, timeOut, 10, 9, timeOut, method)
	}
}

func Test_RemoteExecutionCapability_CapabilityError(t *testing.T) {
	ctx := testutils.Context(t)

	capability := &TestErrorCapability{}

	transmissionSchedule, err := values.NewMap(map[string]any{
		"schedule":   transmission.Schedule_AllAtOnce,
		"deltaStage": "10ms",
	})
	require.NoError(t, err)

	var methods []func(ctx context.Context, caller commoncap.ExecutableCapability)

	methods = append(methods, func(ctx context.Context, caller commoncap.ExecutableCapability) {
		executeCapability(ctx, t, caller, transmissionSchedule, func(t *testing.T, responseCh commoncap.CapabilityResponse, responseError error) {
			assert.Equal(t, "error executing request: failed to execute capability: an error", responseError.Error())
		})
	})

	for _, method := range methods {
		testRemoteExecutableCapability(ctx, t, capability, 10, 9, 10*time.Minute, 10, 9, 10*time.Minute, method)
	}
}

func Test_RemoteExecutableCapability_RandomCapabilityError(t *testing.T) {
	ctx := testutils.Context(t)

	capability := &TestRandomErrorCapability{}

	transmissionSchedule, err := values.NewMap(map[string]any{
		"schedule":   transmission.Schedule_AllAtOnce,
		"deltaStage": "10ms",
	})
	require.NoError(t, err)

	var methods []func(ctx context.Context, caller commoncap.ExecutableCapability)

	methods = append(methods, func(ctx context.Context, caller commoncap.ExecutableCapability) {
		executeCapability(ctx, t, caller, transmissionSchedule, func(t *testing.T, responseCh commoncap.CapabilityResponse, responseError error) {
			assert.Equal(t, "error executing request: request expired", responseError.Error())
		})
	})

	for _, method := range methods {
		testRemoteExecutableCapability(ctx, t, capability, 10, 9, 10*time.Millisecond, 10, 9, 10*time.Minute,
			method)
	}
}

func testRemoteExecutableCapability(ctx context.Context, t *testing.T, underlying commoncap.ExecutableCapability, numWorkflowPeers int, workflowDonF uint8, workflowNodeTimeout time.Duration,
	numCapabilityPeers int, capabilityDonF uint8, capabilityNodeResponseTimeout time.Duration,
	method func(ctx context.Context, caller commoncap.ExecutableCapability)) {
	lggr := logger.TestLogger(t)

	capabilityPeers := make([]p2ptypes.PeerID, numCapabilityPeers)
	for i := 0; i < numCapabilityPeers; i++ {
		capabilityPeerID := p2ptypes.PeerID{}
		require.NoError(t, capabilityPeerID.UnmarshalText([]byte(NewPeerID())))
		capabilityPeers[i] = capabilityPeerID
	}

	capabilityPeerID := p2ptypes.PeerID{}
	require.NoError(t, capabilityPeerID.UnmarshalText([]byte(NewPeerID())))

	capDonInfo := commoncap.DON{
		ID:      2,
		Members: capabilityPeers,
		F:       capabilityDonF,
	}

	capInfo := commoncap.CapabilityInfo{
		ID:             "cap_id@1.0.0",
		CapabilityType: commoncap.CapabilityTypeTarget,
		Description:    "Remote Target",
		DON:            &capDonInfo,
	}

	workflowPeers := make([]p2ptypes.PeerID, numWorkflowPeers)
	for i := 0; i < numWorkflowPeers; i++ {
		workflowPeerID := p2ptypes.PeerID{}
		require.NoError(t, workflowPeerID.UnmarshalText([]byte(NewPeerID())))
		workflowPeers[i] = workflowPeerID
	}

	workflowDonInfo := commoncap.DON{
		Members: workflowPeers,
		ID:      1,
		F:       workflowDonF,
	}

	broker := newTestAsyncMessageBroker(t, 1000)

	workflowDONs := map[uint32]commoncap.DON{
		workflowDonInfo.ID: workflowDonInfo,
	}

	capabilityNodes := make([]remotetypes.Receiver, numCapabilityPeers)
	for i := 0; i < numCapabilityPeers; i++ {
		capabilityPeer := capabilityPeers[i]
		capabilityDispatcher := broker.NewDispatcherForNode(capabilityPeer)
		capabilityNode := executable.NewServer(&commoncap.RemoteExecutableConfig{RequestHashExcludedAttributes: []string{}}, capabilityPeer, underlying, capInfo, capDonInfo, workflowDONs, capabilityDispatcher,
			capabilityNodeResponseTimeout, lggr)
		servicetest.Run(t, capabilityNode)
		broker.RegisterReceiverNode(capabilityPeer, capabilityNode)
		capabilityNodes[i] = capabilityNode
	}

	workflowNodes := make([]commoncap.ExecutableCapability, numWorkflowPeers)
	for i := 0; i < numWorkflowPeers; i++ {
		workflowPeerDispatcher := broker.NewDispatcherForNode(workflowPeers[i])
		workflowNode := executable.NewClient(capInfo, workflowDonInfo, workflowPeerDispatcher, workflowNodeTimeout, lggr)
		servicetest.Run(t, workflowNode)
		broker.RegisterReceiverNode(workflowPeers[i], workflowNode)
		workflowNodes[i] = workflowNode
	}

	servicetest.Run(t, broker)

	wg := &sync.WaitGroup{}
	wg.Add(len(workflowNodes))

	for _, caller := range workflowNodes {
		go func(caller commoncap.ExecutableCapability) {
			defer wg.Done()
			method(ctx, caller)
		}(caller)
	}

	wg.Wait()
}

type testAsyncMessageBroker struct {
	services.Service
	eng *services.Engine
	t   *testing.T

	nodes map[p2ptypes.PeerID]remotetypes.Receiver

	sendCh chan *remotetypes.MessageBody
}

func newTestAsyncMessageBroker(t *testing.T, sendChBufferSize int) *testAsyncMessageBroker {
	b := &testAsyncMessageBroker{
		t:      t,
		nodes:  make(map[p2ptypes.PeerID]remotetypes.Receiver),
		sendCh: make(chan *remotetypes.MessageBody, sendChBufferSize),
	}
	b.Service, b.eng = services.Config{
		Name:  "testAsyncMessageBroker",
		Start: b.start,
	}.NewServiceEngine(logger.TestLogger(t))
	return b
}

func (a *testAsyncMessageBroker) start(ctx context.Context) error {
	a.eng.Go(func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-a.sendCh:
				receiverId := toPeerID(msg.Receiver)

				receiver, ok := a.nodes[receiverId]
				if !ok {
					panic("server not found for peer id")
				}

				receiver.Receive(tests.Context(a.t), msg)
			}
		}
	})
	return nil
}

func (a *testAsyncMessageBroker) NewDispatcherForNode(nodePeerID p2ptypes.PeerID) remotetypes.Dispatcher {
	return &nodeDispatcher{
		callerPeerID: nodePeerID,
		broker:       a,
	}
}

func (a *testAsyncMessageBroker) RegisterReceiverNode(nodePeerID p2ptypes.PeerID, node remotetypes.Receiver) {
	if _, ok := a.nodes[nodePeerID]; ok {
		panic("node already registered")
	}

	a.nodes[nodePeerID] = node
}

func (a *testAsyncMessageBroker) Send(msg *remotetypes.MessageBody) {
	a.sendCh <- msg
}

func toPeerID(id []byte) p2ptypes.PeerID {
	return [32]byte(id)
}

type broker interface {
	Send(msg *remotetypes.MessageBody)
}

type nodeDispatcher struct {
	callerPeerID p2ptypes.PeerID
	broker       broker
}

func (t *nodeDispatcher) Name() string {
	return "nodeDispatcher"
}

func (t *nodeDispatcher) Start(ctx context.Context) error {
	return nil
}

func (t *nodeDispatcher) Close() error {
	return nil
}

func (t *nodeDispatcher) Ready() error {
	return nil
}

func (t *nodeDispatcher) HealthReport() map[string]error {
	return nil
}

func (t *nodeDispatcher) Send(peerID p2ptypes.PeerID, msgBody *remotetypes.MessageBody) error {
	msgBody.Version = 1
	msgBody.Sender = t.callerPeerID[:]
	msgBody.Receiver = peerID[:]
	msgBody.Timestamp = time.Now().UnixMilli()
	t.broker.Send(msgBody)
	return nil
}

func (t *nodeDispatcher) SetReceiver(capabilityId string, donId uint32, receiver remotetypes.Receiver) error {
	return nil
}
func (t *nodeDispatcher) RemoveReceiver(capabilityId string, donId uint32) {}

type abstractTestCapability struct {
}

func (t abstractTestCapability) Info(ctx context.Context) (commoncap.CapabilityInfo, error) {
	return commoncap.CapabilityInfo{}, nil
}

func (t abstractTestCapability) RegisterToWorkflow(ctx context.Context, request commoncap.RegisterToWorkflowRequest) error {
	return nil
}

func (t abstractTestCapability) UnregisterFromWorkflow(ctx context.Context, request commoncap.UnregisterFromWorkflowRequest) error {
	return nil
}

type TestCapability struct {
	abstractTestCapability
}

func (t TestCapability) Execute(ctx context.Context, request commoncap.CapabilityRequest) (commoncap.CapabilityResponse, error) {
	value := request.Inputs.Underlying["executeValue1"]
	response, err := values.NewMap(map[string]any{"response": value})
	if err != nil {
		return commoncap.CapabilityResponse{}, err
	}
	return commoncap.CapabilityResponse{
		Value: response,
	}, nil
}

type TestErrorCapability struct {
	abstractTestCapability
}

func (t TestErrorCapability) Execute(ctx context.Context, request commoncap.CapabilityRequest) (commoncap.CapabilityResponse, error) {
	return commoncap.CapabilityResponse{}, errors.New("an error")
}

func (t TestErrorCapability) RegisterToWorkflow(ctx context.Context, request commoncap.RegisterToWorkflowRequest) error {
	return errors.New("an error")
}

func (t TestErrorCapability) UnregisterFromWorkflow(ctx context.Context, request commoncap.UnregisterFromWorkflowRequest) error {
	return errors.New("an error")
}

type TestRandomErrorCapability struct {
	abstractTestCapability
}

func (t TestRandomErrorCapability) Execute(ctx context.Context, request commoncap.CapabilityRequest) (commoncap.CapabilityResponse, error) {
	return commoncap.CapabilityResponse{}, errors.New(uuid.New().String())
}

func (t TestRandomErrorCapability) RegisterToWorkflow(ctx context.Context, request commoncap.RegisterToWorkflowRequest) error {
	return errors.New(uuid.New().String())
}

func (t TestRandomErrorCapability) UnregisterFromWorkflow(ctx context.Context, request commoncap.UnregisterFromWorkflowRequest) error {
	return errors.New(uuid.New().String())
}

func NewP2PPeerID(t *testing.T) p2ptypes.PeerID {
	id := p2ptypes.PeerID{}
	require.NoError(t, id.UnmarshalText([]byte(NewPeerID())))
	return id
}

func NewPeerID() string {
	var privKey [32]byte
	_, err := rand.Read(privKey[:])
	if err != nil {
		panic(err)
	}

	peerID := append(libp2pMagic(), privKey[:]...)

	return base58.Encode(peerID)
}

func libp2pMagic() []byte {
	return []byte{0x00, 0x24, 0x08, 0x01, 0x12, 0x20}
}

func executeCapability(ctx context.Context, t *testing.T, caller commoncap.ExecutableCapability, transmissionSchedule *values.Map, responseTest func(t *testing.T, response commoncap.CapabilityResponse, responseError error)) {
	executeInputs, err := values.NewMap(
		map[string]any{
			"executeValue1": "aValue1",
		},
	)
	require.NoError(t, err)
	response, err := caller.Execute(ctx,
		commoncap.CapabilityRequest{
			Metadata: commoncap.RequestMetadata{
				WorkflowID:          workflowID1,
				WorkflowExecutionID: workflowExecutionID1,
			},
			Config: transmissionSchedule,
			Inputs: executeInputs,
		})

	responseTest(t, response, err)
}

func registerWorkflow(ctx context.Context, t *testing.T, caller commoncap.ExecutableCapability, transmissionSchedule *values.Map, responseTest func(t *testing.T, responseError error)) {
	err := caller.RegisterToWorkflow(ctx, commoncap.RegisterToWorkflowRequest{
		Metadata: commoncap.RegistrationMetadata{
			WorkflowID:    workflowID1,
			ReferenceID:   stepReferenceID1,
			WorkflowOwner: workflowOwnerID,
		},
		Config: transmissionSchedule,
	})

	responseTest(t, err)
}

func unregisterWorkflow(ctx context.Context, t *testing.T, caller commoncap.ExecutableCapability, transmissionSchedule *values.Map, responseTest func(t *testing.T, responseError error)) {
	err := caller.UnregisterFromWorkflow(ctx, commoncap.UnregisterFromWorkflowRequest{
		Metadata: commoncap.RegistrationMetadata{
			WorkflowID:    workflowID1,
			ReferenceID:   stepReferenceID1,
			WorkflowOwner: workflowOwnerID,
		},
		Config: transmissionSchedule,
	})

	responseTest(t, err)
}