package mcmsnew

import (
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"

	accessControllerBindings "github.com/smartcontractkit/chainlink-ccip/chains/solana/gobindings/access_controller"
	timelockBindings "github.com/smartcontractkit/chainlink-ccip/chains/solana/gobindings/timelock"
	solanaUtils "github.com/smartcontractkit/chainlink-ccip/chains/solana/utils/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/chainlink/deployment/common/changeset/state"
	commontypes "github.com/smartcontractkit/chainlink/deployment/common/types"
)

func deployAccessControllerProgram(
	e deployment.Environment, chainState *state.MCMSWithTimelockStateSolana,
	chain deployment.SolChain, addressBook deployment.AddressBook,
) error {
	typeAndVersion := deployment.NewTypeAndVersion(commontypes.AccessControllerProgram, deployment.Version1_0_0)
	log := logger.With(e.Logger, "chain", chain.String(), "contract", typeAndVersion.String())

	programID, _, err := chainState.GetStateFromType(commontypes.AccessControllerProgram)
	if err != nil {
		return fmt.Errorf("failed to get access controller program state: %w", err)
	}

	if programID.IsZero() {
		deployedProgramID, err := chain.DeployProgram(e.Logger, "access_controller")
		if err != nil {
			return fmt.Errorf("failed to deploy access controller program: %w", err)
		}

		programID, err = solana.PublicKeyFromBase58(deployedProgramID)
		if err != nil {
			return fmt.Errorf("failed to convert mcm program id to public key: %w", err)
		}

		err = addressBook.Save(chain.Selector, programID.String(), typeAndVersion)
		if err != nil {
			return fmt.Errorf("failed to save address: %w", err)
		}

		err = chainState.SetState(commontypes.AccessControllerProgram, programID, state.PDASeed{})
		if err != nil {
			return fmt.Errorf("failed to save onchain state: %w", err)
		}

		log.Infow("deployed access controller contract", "programId", programID)
	} else {
		log.Infow("using existing AccessController program", "programId", programID)
	}

	return nil
}

func initAccessController(
	e deployment.Environment, chainState *state.MCMSWithTimelockStateSolana, contractType deployment.ContractType,
	chain deployment.SolChain, addressBook deployment.AddressBook,
) error {
	if chainState.AccessControllerProgram.IsZero() {
		return errors.New("access controller program is not deployed")
	}
	programID := chainState.AccessControllerProgram
	accessControllerBindings.SetProgramID(programID)

	typeAndVersion := deployment.NewTypeAndVersion(contractType, deployment.Version1_0_0)
	log := logger.With(e.Logger, "chain", chain.String(), "contract", typeAndVersion.String(), "programID", programID)

	account, err := solana.NewRandomPrivateKey() // FIXME: what should we do with the account private key?
	if err != nil {
		return fmt.Errorf("failed to generate new random private key for access controller account: %w", err)
	}

	err = initializeAccessController(e, chain, programID, account)
	if err != nil {
		return fmt.Errorf("failed to initialize access controller: %w", err)
	}
	log.Infow("initialized access controller", "account", account.PublicKey())

	address := state.EncodeAddressWithAccount(programID, account.PublicKey())
	err = addressBook.Save(chain.Selector, address, typeAndVersion)
	if err != nil {
		return fmt.Errorf("failed to save address: %w", err)
	}

	err = chainState.SetState(contractType, programID, state.PDASeed(account.PublicKey()))
	if err != nil {
		return fmt.Errorf("failed to save onchain state: %w", err)
	}

	return nil
}

// discriminator + owner + proposed owner + access_list (64 max addresses + length)
const accessControllerAccountSize = uint64(8 + 32 + 32 + ((32 * 64) + 8))

func initializeAccessController(
	e deployment.Environment, chain deployment.SolChain, programID solana.PublicKey, account solana.PrivateKey,
) error {
	rentExemption, err := chain.Client.GetMinimumBalanceForRentExemption(e.GetContext(),
		accessControllerAccountSize, rpc.CommitmentConfirmed)
	if err != nil {
		return fmt.Errorf("failed to get minimum balance for rent exemption: %w", err)
	}

	createAccountInstruction, err := system.NewCreateAccountInstruction(rentExemption, accessControllerAccountSize,
		programID, chain.DeployerKey.PublicKey(), account.PublicKey()).ValidateAndBuild()
	if err != nil {
		return fmt.Errorf("failed to create CreateAccount instruction: %w", err)
	}

	initializeInstruction, err := accessControllerBindings.NewInitializeInstruction(
		account.PublicKey(),
		chain.DeployerKey.PublicKey(),
	).ValidateAndBuild()
	if err != nil {
		return fmt.Errorf("failed to build instruction: %w", err)
	}

	instructions := []solana.Instruction{createAccountInstruction, initializeInstruction}
	err = chain.Confirm(instructions, solanaUtils.AddSigners(account))
	if err != nil {
		return fmt.Errorf("failed to confirm CreateAccount and InitializeAccessController instructions: %w", err)
	}

	var data accessControllerBindings.AccessController
	err = solanaUtils.GetAccountDataBorshInto(e.GetContext(), chain.Client, account.PublicKey(), rpc.CommitmentConfirmed, &data)
	if err != nil {
		return fmt.Errorf("failed to read access controller account: %w", err)
	}

	return nil
}

func setupRoles(chainState *state.MCMSWithTimelockStateSolana, chain deployment.SolChain) error {
	proposerPDA := GetMCMSignerPDA(chainState.McmProgram, chainState.ProposerMcmSeed)
	cancellerPDA := GetMCMSignerPDA(chainState.McmProgram, chainState.CancellerMcmSeed)
	bypasserPDA := GetMCMSignerPDA(chainState.McmProgram, chainState.BypasserMcmSeed)

	err := addAccess(chain, chainState, timelockBindings.Proposer_Role, proposerPDA)
	if err != nil {
		return fmt.Errorf("failed to add access for proposer role: %w", err)
	}

	err = addAccess(chain, chainState, timelockBindings.Executor_Role, chain.DeployerKey.PublicKey())
	if err != nil {
		return fmt.Errorf("failed to add access for executor role: %w", err)
	}

	err = addAccess(chain, chainState, timelockBindings.Canceller_Role, cancellerPDA, proposerPDA, bypasserPDA)
	if err != nil {
		return fmt.Errorf("failed to add access for canceller role: %w", err)
	}

	err = addAccess(chain, chainState, timelockBindings.Bypasser_Role, bypasserPDA)
	if err != nil {
		return fmt.Errorf("failed to add access for bypasser role: %w", err)
	}

	return nil
}

func addAccess(
	chain deployment.SolChain, chainState *state.MCMSWithTimelockStateSolana,
	role timelockBindings.Role, accounts ...solana.PublicKey,
) error {
	timelockConfigPDA := GetTimelockConfigPDA(chainState.TimelockProgram, chainState.TimelockSeed)

	instructionBuilder := timelockBindings.NewBatchAddAccessInstruction([32]uint8(chainState.TimelockSeed), role,
		timelockConfigPDA, chainState.AccessControllerProgram, chainState.RoleAccount(role), chain.DeployerKey.PublicKey())
	for _, account := range accounts {
		instructionBuilder.Append(solana.Meta(account))
	}

	instruction, err := instructionBuilder.ValidateAndBuild()
	if err != nil {
		return fmt.Errorf("failed to build BatchAddAccess instruction: %w", err)
	}

	err = chain.Confirm([]solana.Instruction{instruction})
	if err != nil {
		return fmt.Errorf("failed to confirm BatchAddAccess instruction: %w", err)
	}

	return nil
}
