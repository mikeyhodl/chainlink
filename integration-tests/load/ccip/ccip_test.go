package ccip

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/math"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink/deployment"

	"github.com/smartcontractkit/chainlink-ccip/pkg/types/ccipocr3"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
	ccipchangeset "github.com/smartcontractkit/chainlink/deployment/ccip/changeset"
	"github.com/smartcontractkit/chainlink/deployment/environment/crib"
	tc "github.com/smartcontractkit/chainlink/integration-tests/testconfig"
)

var (
	CommonTestLabels = map[string]string{
		"branch": "ccip_load_1_6",
		"commit": "ccip_load_1_6",
	}
	wg sync.WaitGroup
)

// todo: add multiple keys and rotate them when sending messages
// this key only works on simulated geth chains in crib
const simChainTestKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// step 1: setup
// Parse the test config, initialize CRIB with configurations defined
// step 2: subscribe
// Create event subscribers on the offramp
// step 3: load
// Use wasp to initiate load
// step 4: teardown
// Stop the chains, cleanup the environment
func TestCCIPLoad_RPS(t *testing.T) {
	// comment out when executing the test
	// t.Skip("Skipping test as this test should not be auto triggered")
	lggr := logger.Test(t)
	ctx, cancel := context.WithCancel(tests.Context(t))
	defer cancel()

	// get user defined configurations
	config, err := tc.GetConfig([]string{"Load"}, tc.CCIP)
	require.NoError(t, err)
	userOverrides := config.CCIP.Load

	// generate environment from crib-produced files
	cribEnv := crib.NewDevspaceEnvFromStateDir(*userOverrides.CribEnvDirectory)
	cribDeployOutput, err := cribEnv.GetConfig(simChainTestKey)
	require.NoError(t, err)
	env, err := crib.NewDeployEnvironmentFromCribOutput(lggr, cribDeployOutput)
	require.NoError(t, err)
	require.NotNil(t, env)
	userOverrides.Validate(t, env)

	// initialize additional accounts on other chains
	transmitKeys, err := fundAdditionalKeys(lggr, *env, env.AllChainSelectors()[:*userOverrides.NumDestinationChains])
	require.NoError(t, err)
	// todo: defer returning funds

	// Keep track of the block number for each chain so that event subscription can be done from that block.
	startBlocks := make(map[uint64]*uint64)
	state, err := ccipchangeset.LoadOnchainState(*env)
	require.NoError(t, err)

	errChan := make(chan error)
	defer close(errChan)
	finalSeqNrCommitChannels := make(map[uint64]chan finalSeqNrReport)
	finalSeqNrExecChannels := make(map[uint64]chan finalSeqNrReport)

	mm := NewMetricsManager(t, env.Logger)
	go mm.Start(ctx)
	defer mm.Stop()

	// gunMap holds a destinationGun for every enabled destination chain
	gunMap := make(map[uint64]*DestinationGun)
	p := wasp.NewProfile()
	// Only create a destination gun if we have decided to send traffic to this chain
	for ind := range *userOverrides.NumDestinationChains {
		cs := env.AllChainSelectors()[ind]
		latesthdr, err := env.Chains[cs].Client.HeaderByNumber(ctx, nil)
		require.NoError(t, err)
		block := latesthdr.Number.Uint64()
		startBlocks[cs] = &block

		messageKeys := make(map[uint64]*bind.TransactOpts)
		other := env.AllChainSelectorsExcluding([]uint64{cs})
		var mu sync.Mutex
		var wg2 sync.WaitGroup
		wg2.Add(len(other))
		for _, src := range other {
			go func(src uint64) {
				defer wg2.Done()
				mu.Lock()
				messageKeys[src] = transmitKeys[src][ind]
				mu.Unlock()
				err := prepareAccountToSendLink(
					t,
					state,
					*env,
					src,
					messageKeys[src],
				)
				require.NoError(t, err)
			}(src)
		}
		wg2.Wait()

		gunMap[cs], err = NewDestinationGun(
			env.Logger,
			cs,
			*env,
			&state,
			state.Chains[cs].Receiver.Address(),
			userOverrides,
			messageKeys,
			ind,
			mm.InputChan,
		)
		if err != nil {
			lggr.Errorw("Failed to initialize DestinationGun for", "chainSelector", cs, "error", err)
			t.Fatal(err)
		}

		otherChains := env.AllChainSelectorsExcluding([]uint64{cs})
		finalSeqNrCommitChannels[cs] = make(chan finalSeqNrReport)
		finalSeqNrExecChannels[cs] = make(chan finalSeqNrReport)

		wg.Add(2)
		go subscribeCommitEvents(
			ctx,
			lggr,
			state.Chains[cs].OffRamp,
			otherChains,
			&block,
			cs,
			env.Chains[cs].Client,
			finalSeqNrCommitChannels[cs],
			errChan,
			&wg,
			mm.InputChan)
		go subscribeExecutionEvents(
			ctx,
			lggr,
			state.Chains[cs].OffRamp,
			otherChains,
			&block,
			cs,
			env.Chains[cs].Client,
			finalSeqNrExecChannels[cs],
			errChan,
			&wg,
			mm.InputChan)
	}

	requestFrequency, err := time.ParseDuration(*userOverrides.RequestFrequency)
	require.NoError(t, err)

	for _, gun := range gunMap {
		p.Add(wasp.NewGenerator(&wasp.Config{
			T:           t,
			GenName:     "ccipLoad",
			LoadType:    wasp.RPS,
			CallTimeout: userOverrides.GetLoadDuration(),
			// 1 request per second for n seconds
			Schedule: wasp.Plain(1, userOverrides.GetLoadDuration()),
			// limit requests to 1 per duration
			RateLimitUnitDuration: requestFrequency,
			// will need to be divided by number of chains
			// this schedule is per generator
			// in this example, it would be 1 request per 5seconds per generator (dest chain)
			// so if there are 3 generators, it would be 3 requests per 5 seconds over the network
			Gun:        gun,
			Labels:     CommonTestLabels,
			LokiConfig: wasp.NewEnvLokiConfig(),
			// use the same loki client using `NewLokiClient` with the same config for sending events
		}))
	}

	_, err = p.Run(true)
	require.NoError(t, err)

	for _, gun := range gunMap {
		for csPair, seqNums := range gun.seqNums {
			lggr.Debugw("pushing finalized sequence numbers for ",
				"chainSelector", gun.chainSelector,
				"sourceChainSelector", csPair.SourceChainSelector,
				"seqNums", seqNums)
			finalSeqNrCommitChannels[csPair.DestChainSelector] <- finalSeqNrReport{
				sourceChainSelector: csPair.SourceChainSelector,
				expectedSeqNrRange: ccipocr3.SeqNumRange{
					ccipocr3.SeqNum(seqNums.Start.Load()), ccipocr3.SeqNum(seqNums.End.Load()),
				},
			}

			finalSeqNrExecChannels[csPair.DestChainSelector] <- finalSeqNrReport{
				sourceChainSelector: csPair.SourceChainSelector,
				expectedSeqNrRange: ccipocr3.SeqNumRange{
					ccipocr3.SeqNum(seqNums.Start.Load()), ccipocr3.SeqNum(seqNums.End.Load()),
				},
			}
		}
	}

	// after load is finished, wait for a "timeout duration" before considering that messages are timed out
	timeout := userOverrides.GetTimeoutDuration()
	if timeout != 0 {
		testTimer := time.NewTimer(timeout)
		go func() {
			<-testTimer.C
			mm.Stop()
			cancel()
		}()
	}

	wg.Wait()
	lggr.Infow("closed event subscribers")
}

func prepareAccountToSendLink(
	t *testing.T,
	state ccipchangeset.CCIPOnChainState,
	e deployment.Environment,
	src uint64,
	srcAccount *bind.TransactOpts) error {
	lggr := logger.Test(t)
	srcDeployer := e.Chains[src].DeployerKey
	lggr.Infow("Setting up link token", "src", src)
	srcLink := state.Chains[src].LinkToken

	lggr.Infow("Granting mint and burn roles")
	tx, err := srcLink.GrantMintAndBurnRoles(srcDeployer, srcAccount.From)
	_, err = deployment.ConfirmIfNoError(e.Chains[src], tx, err)
	require.NoError(t, err)

	lggr.Infow("Minting transfer amounts")
	//--------------------------------------------------------------------------------------------
	tx, err = srcLink.Mint(
		srcAccount,
		srcAccount.From,
		big.NewInt(20_000),
	)
	_, err = deployment.ConfirmIfNoError(e.Chains[src], tx, err)
	if err != nil {
		return err
	}

	//--------------------------------------------------------------------------------------------
	lggr.Infow("Approving routers")
	// Approve the router to spend the tokens and confirm the tx's
	// To prevent having to approve the router for every transfer, we approve a sufficiently large amount
	tx, err = srcLink.Approve(srcAccount, state.Chains[src].Router.Address(), math.MaxBig256)
	_, err = deployment.ConfirmIfNoError(e.Chains[src], tx, err)
	return err
}
