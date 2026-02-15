use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio_system::instructions::Transfer as SystemTransfer;
use solana_program_error::ProgramError;
use solana_program_log::log;

use crate::state::ShieldedPoolState;

pub fn process_deposit(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Accounts: [payer, state, vault, system_program]
    let [payer, state_account, vault, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !state_account.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Data layout: [amount: u64] [commitment: [u8; 32]] [new_root: [u8; 32]]
    if data.len() != 72 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().map_err(|_| {
        ProgramError::InvalidInstructionData
    })?);
    let commitment: [u8; 32] = data[8..40]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let new_root: [u8; 32] = data[40..72]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // C-03 mitigation: Prevent zero-amount deposits that allow root injection without economic cost.
    // An attacker can inject an arbitrary Merkle root via a zero-lamport deposit, then withdraw
    // the entire vault balance using a ZK proof crafted against their injected root.
    if amount == 0 {
        log("Deposit amount must be greater than zero");
        return Err(ProgramError::InvalidInstructionData);
    }

    log("Processing Deposit");

    // Transfer SOL to the vault.
    SystemTransfer {
        from: payer,
        to: vault,
        lamports: amount,
    }
    .invoke()?;

    // Update the stored Merkle root.
    if state_account.address() != &Address::find_program_address(&[b"pool_state"], &crate::ID).0 {
        return Err(ProgramError::InvalidAccountData);
    }

    if !state_account.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    if vault.address() != &Address::find_program_address(&[b"vault"], &crate::ID).0 {
        return Err(ProgramError::InvalidAccountData);
    }

    if !vault.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut state_data = state_account.try_borrow_mut()?;
    let state: &mut ShieldedPoolState =
        bytemuck::from_bytes_mut(&mut state_data[..ShieldedPoolState::LEN]);

    if !state.is_initialized() {
        return Err(ProgramError::UninitializedAccount);
    }

    // TODO(C-01/C-02): The root MUST be computed on-chain from the commitment, not accepted from
    // instruction data. The current design allows any caller to inject an arbitrary Merkle root.
    // Fix requires:
    //   1. Store commitments (leaves) in an on-chain Merkle tree account
    //   2. Insert `commitment` into the tree on deposit
    //   3. Compute and store the new root from the tree — never from client data
    //   4. Remove `new_root` from instruction data entirely
    // Until then, the pool's root-of-trust is fundamentally broken: any deposit can overwrite the
    // Merkle root, enabling a vault drain via crafted ZK proofs against attacker-controlled roots.
    let _ = commitment; // Used after on-chain Merkle tree is implemented (see TODO above)
    state.add_root(new_root);

    log("Deposit successful, root updated");
    Ok(())
}
