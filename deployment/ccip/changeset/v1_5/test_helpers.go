package v1_5

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/confighelper"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccip"

	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset"
	commonchangeset "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	"github.com/smartcontractkit/chainlink/deployment/environment/memory"
	"github.com/smartcontractkit/chainlink/v2/core/gethwrappers/ccip/generated/commit_store"
	"github.com/smartcontractkit/chainlink/v2/core/gethwrappers/ccip/generated/evm_2_evm_offramp"
	"github.com/smartcontractkit/chainlink/v2/core/gethwrappers/ccip/generated/evm_2_evm_onramp"
	"github.com/smartcontractkit/chainlink/v2/core/gethwrappers/ccip/generated/price_registry_1_2_0"
	"github.com/smartcontractkit/chainlink/v2/core/services/ocr2/plugins/ccip/testhelpers"
)

func AddLanes(t *testing.T, e deployment.Environment, state changeset.CCIPOnChainState, pairs []changeset.SourceDestPair) deployment.Environment {
	addLanesCfg, commitOCR2Configs, execOCR2Configs, jobspecs := LaneConfigsForChains(t, e, state, pairs)
	var err error
	e, err = commonchangeset.ApplyChangesets(t, e, nil, []commonchangeset.ChangesetApplication{
		{
			Changeset: commonchangeset.WrapChangeSet(DeployLanes),
			Config: DeployLanesConfig{
				Configs: addLanesCfg,
			},
		},
		{
			Changeset: commonchangeset.WrapChangeSet(SetOCR2ConfigForTest),
			Config: OCR2Config{
				CommitConfigs: commitOCR2Configs,
				ExecConfigs:   execOCR2Configs,
			},
		},
		{
			Changeset: commonchangeset.WrapChangeSet(JobSpecsForLanes),
			Config: JobSpecsForLanesConfig{
				Configs: jobspecs,
			},
		},
	})
	require.NoError(t, err)
	return e
}

func LaneConfigsForChains(t *testing.T, env deployment.Environment, state changeset.CCIPOnChainState, pairs []changeset.SourceDestPair) (
	[]DeployLaneConfig,
	[]CommitOCR2ConfigParams,
	[]ExecuteOCR2ConfigParams,
	[]JobSpecInput,
) {
	var addLanesCfg []DeployLaneConfig
	var commitOCR2Configs []CommitOCR2ConfigParams
	var execOCR2Configs []ExecuteOCR2ConfigParams
	var jobSpecs []JobSpecInput
	for _, pair := range pairs {
		dest := pair.DestChainSelector
		src := pair.SourceChainSelector
		sourceChainState := state.Chains[src]
		destChainState := state.Chains[dest]
		require.NotNil(t, sourceChainState.LinkToken)
		require.NotNil(t, sourceChainState.RMNProxy)
		require.NotNil(t, sourceChainState.TokenAdminRegistry)
		require.NotNil(t, sourceChainState.Router)
		require.NotNil(t, sourceChainState.PriceRegistry)
		require.NotNil(t, sourceChainState.Weth9)
		require.NotNil(t, destChainState.LinkToken)
		require.NotNil(t, destChainState.RMNProxy)
		require.NotNil(t, destChainState.TokenAdminRegistry)
		tokenPrice, _, _ := CreatePricesPipeline(t, state, src, dest)
		block, err := env.Chains[dest].Client.HeaderByNumber(context.Background(), nil)
		require.NoError(t, err)
		destEVMChainIdStr, err := chain_selectors.GetChainIDFromSelector(dest)
		require.NoError(t, err)
		destEVMChainId, err := strconv.ParseUint(destEVMChainIdStr, 10, 64)
		require.NoError(t, err)
		jobSpecs = append(jobSpecs, JobSpecInput{
			SourceChainSelector:      src,
			DestinationChainSelector: dest,
			DestEVMChainID:           destEVMChainId,
			TokenPricesUSDPipeline:   tokenPrice,
			DestinationStartBlock:    block.Number.Uint64(),
		})
		addLanesCfg = append(addLanesCfg, DeployLaneConfig{
			SourceChainSelector:      src,
			DestinationChainSelector: dest,
			OnRampStaticCfg: evm_2_evm_onramp.EVM2EVMOnRampStaticConfig{
				LinkToken:          sourceChainState.LinkToken.Address(),
				ChainSelector:      src,
				DestChainSelector:  dest,
				DefaultTxGasLimit:  200_000,
				MaxNopFeesJuels:    big.NewInt(0).Mul(big.NewInt(100_000_000), big.NewInt(1e18)),
				PrevOnRamp:         common.Address{},
				RmnProxy:           sourceChainState.RMNProxy.Address(),
				TokenAdminRegistry: sourceChainState.TokenAdminRegistry.Address(),
			},
			OnRampDynamicCfg: evm_2_evm_onramp.EVM2EVMOnRampDynamicConfig{
				Router:                            sourceChainState.Router.Address(),
				MaxNumberOfTokensPerMsg:           5,
				DestGasOverhead:                   350_000,
				DestGasPerPayloadByte:             16,
				DestDataAvailabilityOverheadGas:   33_596,
				DestGasPerDataAvailabilityByte:    16,
				DestDataAvailabilityMultiplierBps: 6840,
				PriceRegistry:                     sourceChainState.PriceRegistry.Address(),
				MaxDataBytes:                      1e5,
				MaxPerMsgGasLimit:                 4_000_000,
				DefaultTokenFeeUSDCents:           50,
				DefaultTokenDestGasOverhead:       125_000,
			},
			OnRampFeeTokenArgs: []evm_2_evm_onramp.EVM2EVMOnRampFeeTokenConfigArgs{
				{
					Token:                      sourceChainState.LinkToken.Address(),
					NetworkFeeUSDCents:         1_00,
					GasMultiplierWeiPerEth:     1e18,
					PremiumMultiplierWeiPerEth: 9e17,
					Enabled:                    true,
				},
				{
					Token:                      sourceChainState.Weth9.Address(),
					NetworkFeeUSDCents:         1_00,
					GasMultiplierWeiPerEth:     1e18,
					PremiumMultiplierWeiPerEth: 1e18,
					Enabled:                    true,
				},
			},
			OnRampTransferTokenCfgs: []evm_2_evm_onramp.EVM2EVMOnRampTokenTransferFeeConfigArgs{
				{
					Token:                     sourceChainState.LinkToken.Address(),
					MinFeeUSDCents:            50,           // $0.5
					MaxFeeUSDCents:            1_000_000_00, // $ 1 million
					DeciBps:                   5_0,          // 5 bps
					DestGasOverhead:           350_000,
					DestBytesOverhead:         32,
					AggregateRateLimitEnabled: true,
				},
			},
			OnRampNopsAndWeight: []evm_2_evm_onramp.EVM2EVMOnRampNopAndWeight{},
			OnRampRateLimiterCfg: evm_2_evm_onramp.RateLimiterConfig{
				IsEnabled: true,
				Capacity:  testhelpers.LinkUSDValue(100),
				Rate:      testhelpers.LinkUSDValue(1),
			},
			OffRampRateLimiterCfg: evm_2_evm_offramp.RateLimiterConfig{
				IsEnabled: true,
				Capacity:  testhelpers.LinkUSDValue(100),
				Rate:      testhelpers.LinkUSDValue(1),
			},
			InitialTokenPrices: []price_registry_1_2_0.InternalTokenPriceUpdate{
				{
					SourceToken: sourceChainState.LinkToken.Address(),
					UsdPerToken: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(20)),
				},
				{
					SourceToken: sourceChainState.Weth9.Address(),
					UsdPerToken: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(2000)),
				},
			},
			GasPriceUpdates: []price_registry_1_2_0.InternalGasPriceUpdate{
				{
					DestChainSelector: dest,
					UsdPerUnitGas:     big.NewInt(20000e9),
				},
			},
		})
		commitOCR2Configs = append(commitOCR2Configs, CommitOCR2ConfigParams{
			SourceChainSelector:      src,
			DestinationChainSelector: dest,
			OCR2ConfigParams:         DefaultOCRParams(),
			GasPriceHeartBeat:        *config.MustNewDuration(10 * time.Second),
			DAGasPriceDeviationPPB:   1,
			ExecGasPriceDeviationPPB: 1,
			TokenPriceHeartBeat:      *config.MustNewDuration(10 * time.Second),
			TokenPriceDeviationPPB:   1,
			InflightCacheExpiry:      *config.MustNewDuration(5 * time.Second),
			PriceReportingDisabled:   false,
		})
		execOCR2Configs = append(execOCR2Configs, ExecuteOCR2ConfigParams{
			DestinationChainSelector:    dest,
			SourceChainSelector:         src,
			DestOptimisticConfirmations: 1,
			BatchGasLimit:               5_000_000,
			RelativeBoostPerWaitHour:    0.07,
			InflightCacheExpiry:         *config.MustNewDuration(1 * time.Minute),
			RootSnoozeTime:              *config.MustNewDuration(1 * time.Minute),
			BatchingStrategyID:          0,
			MessageVisibilityInterval:   config.Duration{},
			ExecOnchainConfig: evm_2_evm_offramp.EVM2EVMOffRampDynamicConfig{
				PermissionLessExecutionThresholdSeconds: uint32(24 * time.Hour.Seconds()),
				MaxDataBytes:                            1e5,
				MaxNumberOfTokensPerMsg:                 5,
			},
			OCR2ConfigParams: DefaultOCRParams(),
		})
	}
	return addLanesCfg, commitOCR2Configs, execOCR2Configs, jobSpecs
}

func CreatePricesPipeline(t *testing.T, state changeset.CCIPOnChainState, source, dest uint64) (string, *httptest.Server, *httptest.Server) {
	sourceRouter := state.Chains[source].Router
	destRouter := state.Chains[dest].Router
	destLink := state.Chains[dest].LinkToken
	linkUSD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"UsdPerLink": "8000000000000000000"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(linkUSD.Close)

	ethUSD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"UsdPerETH": "1700000000000000000000"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(ethUSD.Close)

	sourceWrappedNative, err := sourceRouter.GetWrappedNative(nil)
	require.NoError(t, err)
	destWrappedNative, err := destRouter.GetWrappedNative(nil)
	require.NoError(t, err)
	tokenPricesUSDPipeline := fmt.Sprintf(`
// Price 1
link [type=http method=GET url="%s"];
link_parse [type=jsonparse path="UsdPerLink"];
link->link_parse;
eth [type=http method=GET url="%s"];
eth_parse [type=jsonparse path="UsdPerETH"];
eth->eth_parse;
merge [type=merge left="{}" right="{\\\"%s\\\":$(link_parse), \\\"%s\\\":$(eth_parse), \\\"%s\\\":$(eth_parse)}"];`,
		linkUSD.URL, ethUSD.URL, destLink.Address(), sourceWrappedNative, destWrappedNative)

	return tokenPricesUSDPipeline, linkUSD, ethUSD
}

func DefaultOCRParams() confighelper.PublicConfig {
	return confighelper.PublicConfig{
		DeltaProgress:                           2 * time.Second,
		DeltaResend:                             1 * time.Second,
		DeltaRound:                              1 * time.Second,
		DeltaGrace:                              500 * time.Millisecond,
		DeltaStage:                              2 * time.Second,
		RMax:                                    3,
		MaxDurationInitialization:               nil,
		MaxDurationQuery:                        50 * time.Millisecond,
		MaxDurationObservation:                  1 * time.Second,
		MaxDurationReport:                       100 * time.Millisecond,
		MaxDurationShouldAcceptFinalizedReport:  100 * time.Millisecond,
		MaxDurationShouldTransmitAcceptedReport: 100 * time.Millisecond,
	}
}

func SendRequest(
	t *testing.T,
	e deployment.Environment,
	state changeset.CCIPOnChainState,
	opts ...changeset.SendReqOpts,
) (*evm_2_evm_onramp.EVM2EVMOnRampCCIPSendRequested, error) {
	cfg := &changeset.CCIPSendReqConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	// Set default sender if not provided
	if cfg.Sender == nil {
		cfg.Sender = e.Chains[cfg.SourceChain].DeployerKey
	}
	t.Logf("Sending CCIP request from chain selector %d to chain selector %d from sender %s",
		cfg.SourceChain, cfg.DestChain, cfg.Sender.From.String())
	tx, blockNum, err := changeset.CCIPSendRequest(e, state, cfg)
	if err != nil {
		return nil, err
	}

	onRamp := state.Chains[cfg.SourceChain].EVM2EVMOnRamp[cfg.DestChain]

	it, err := onRamp.FilterCCIPSendRequested(&bind.FilterOpts{
		Start:   blockNum,
		End:     &blockNum,
		Context: context.Background(),
	})
	if err != nil {
		return nil, err
	}

	require.True(t, it.Next())
	t.Logf("CCIP message (id %x) sent from chain selector %d to chain selector %d tx %s seqNum %d sender %s",
		it.Event.Message.MessageId[:],
		cfg.SourceChain,
		cfg.DestChain,
		tx.Hash().String(),
		it.Event.Message.SequenceNumber,
		it.Event.Message.Sender.String(),
	)
	return it.Event, nil
}

func WaitForCommit(
	t *testing.T,
	src deployment.Chain,
	dest deployment.Chain,
	commitStore *commit_store.CommitStore,
	seqNr uint64,
) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if backend, ok := src.Client.(*memory.Backend); ok {
				backend.Commit()
			}
			if backend, ok := dest.Client.(*memory.Backend); ok {
				backend.Commit()
			}
			minSeqNr, err := commitStore.GetExpectedNextSequenceNumber(nil)
			require.NoError(t, err)
			t.Logf("Waiting for commit for sequence number %d, current min sequence number %d", seqNr, minSeqNr)
			if minSeqNr > seqNr {
				t.Logf("Commit for sequence number %d found", seqNr)
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for commit for sequence number %d for commit store %s ", seqNr, commitStore.Address().String())
			return
		}
	}
}

func WaitForExecute(
	t *testing.T,
	src deployment.Chain,
	dest deployment.Chain,
	offRamp *evm_2_evm_offramp.EVM2EVMOffRamp,
	seqNrs []uint64,
	blockNum uint64,
) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if backend, ok := src.Client.(*memory.Backend); ok {
				backend.Commit()
			}
			if backend, ok := dest.Client.(*memory.Backend); ok {
				backend.Commit()
			}
			t.Logf("Waiting for execute for sequence numbers %v", seqNrs)
			it, err := offRamp.FilterExecutionStateChanged(
				&bind.FilterOpts{
					Start: blockNum,
				}, seqNrs, [][32]byte{})
			require.NoError(t, err)
			for it.Next() {
				t.Logf("Execution state changed for sequence number=%d current state=%d", it.Event.SequenceNumber, it.Event.State)
				if cciptypes.MessageExecutionState(it.Event.State) == cciptypes.ExecutionStateSuccess {
					t.Logf("Execution for sequence number %d found", it.Event.SequenceNumber)
					return
				}
				t.Logf("Execution for sequence number %d resulted in status %d", it.Event.SequenceNumber, it.Event.State)
				t.Fail()
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for execute for sequence numbers %v for offramp %s ", seqNrs, offRamp.Address().String())
			return
		}
	}
}