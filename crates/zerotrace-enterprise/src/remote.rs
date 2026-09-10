//! Signed remote commands.
//!
//! The organization holds an Ed25519 signing key. ZeroTrace holds only the
//! public half, so a compromised endpoint cannot forge instructions to other
//! endpoints, and the server never possesses vault keys or plaintext.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zerotrace_core::{Error, Result, VaultId};

/// What an organization may instruct an endpoint to do.
///
/// The set is deliberately small. Anything that reads vault contents is absent
/// on purpose: the server must never be able to obtain plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandAction {
    /// Close sessions and clear resident keys. Never destroys.
    Lock,
    /// Require a fresh check-in before the deadline resumes counting.
    RequireCheckIn,
    /// Shorten the deadman timeout. Cannot lengthen it: see `is_weakening`.
    TightenPolicy { timeout_seconds: u64 },
    /// Destroy the vault. Still goes through two-phase authorization locally.
    Destroy,
}

impl CommandAction {
    pub fn label(&self) -> &'static str {
        match self {
            CommandAction::Lock => "LOCK",
            CommandAction::RequireCheckIn => "REQUIRE_CHECK_IN",
            CommandAction::TightenPolicy { .. } => "TIGHTEN_POLICY",
            CommandAction::Destroy => "DESTROY",
        }
    }

    /// Whether the action reduces protection.
    ///
    /// A signed command must never be able to weaken a vault: an attacker who
    /// obtains the org key could otherwise disarm every endpoint quietly,
    /// which is worse than destroying them loudly.
    pub fn is_weakening(&self, current_timeout: u64) -> bool {
        match self {
            CommandAction::TightenPolicy { timeout_seconds } => *timeout_seconds > current_timeout,
            _ => false,
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(self, CommandAction::Destroy)
    }
}

/// A command as issued by an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCommand {
    pub vault_id: VaultId,
    pub action: CommandAction,
    /// Unique per command. Replaying a command with a seen nonce is refused.
    pub nonce: [u8; 16],
    pub issued_at: i64,
    /// After this, the command is refused however well signed it is.
    pub expires_at: i64,
    pub signature: Vec<u8>,
}

impl RemoteCommand {
    /// The bytes the signature covers.
    ///
    /// Every field is included and length-prefixed, so no field can be altered
    /// or moved between commands without invalidating the signature.
    fn signing_payload(
        vault_id: &VaultId,
        action: &CommandAction,
        nonce: &[u8; 16],
        issued_at: i64,
        expires_at: i64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(b"apex-zerotrace:remote-command:v1");
        b.extend_from_slice(vault_id.as_bytes());
        let label = action.label().as_bytes();
        b.extend_from_slice(&(label.len() as u32).to_le_bytes());
        b.extend_from_slice(label);
        if let CommandAction::TightenPolicy { timeout_seconds } = action {
            b.extend_from_slice(&timeout_seconds.to_le_bytes());
        }
        b.extend_from_slice(nonce);
        b.extend_from_slice(&issued_at.to_le_bytes());
        b.extend_from_slice(&expires_at.to_le_bytes());
        b
    }
}

/// An organization's signing key. Never present on an endpoint.
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        zerotrace_crypto::random_bytes(&mut seed);
        Self { key: SigningKey::from_bytes(&seed) }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The public half, which is what an endpoint stores.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn issue(
        &self,
        vault_id: VaultId,
        action: CommandAction,
        issued_at: i64,
        valid_for_seconds: i64,
    ) -> RemoteCommand {
        let mut nonce = [0u8; 16];
        zerotrace_crypto::random_bytes(&mut nonce);
        let expires_at = issued_at + valid_for_seconds;
        let payload =
            RemoteCommand::signing_payload(&vault_id, &action, &nonce, issued_at, expires_at);
        let signature: Signature = self.key.sign(&payload);
        RemoteCommand {
            vault_id,
            action,
            nonce,
            issued_at,
            expires_at,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

/// Nonces already seen, so a captured command cannot be replayed.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: std::collections::HashSet<[u8; 16]>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn remember(&mut self, nonce: [u8; 16]) {
        self.seen.insert(nonce);
    }
    pub fn has_seen(&self, nonce: &[u8; 16]) -> bool {
        self.seen.contains(nonce)
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Why a command was accepted or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandVerdict {
    Accepted,
    BadSignature,
    WrongVault,
    Expired,
    NotYetValid,
    Replayed,
    /// The command would reduce protection, so it is refused regardless of
    /// how well it is signed.
    WouldWeaken,
}

impl CommandVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            CommandVerdict::Accepted => "ACCEPTED",
            CommandVerdict::BadSignature => "REFUSED: signature does not verify",
            CommandVerdict::WrongVault => "REFUSED: issued for a different vault",
            CommandVerdict::Expired => "REFUSED: expired",
            CommandVerdict::NotYetValid => "REFUSED: issued in the future",
            CommandVerdict::Replayed => "REFUSED: nonce already used",
            CommandVerdict::WouldWeaken => "REFUSED: would reduce protection",
        }
    }
    pub fn is_accepted(&self) -> bool {
        *self == CommandVerdict::Accepted
    }
}

/// Checks a command against every rule before it may be acted on.
///
/// Order matters only for the error reported; every rule is applied.
pub fn verify_command(
    command: &RemoteCommand,
    org_public_key: &[u8; 32],
    expected_vault: VaultId,
    now: i64,
    current_timeout: u64,
    guard: &ReplayGuard,
) -> Result<CommandVerdict> {
    if command.vault_id != expected_vault {
        return Ok(CommandVerdict::WrongVault);
    }
    if now > command.expires_at {
        return Ok(CommandVerdict::Expired);
    }
    // A command dated in the future suggests a clock problem at one end, and
    // acting on it would let a long-lived command be banked for later.
    if command.issued_at > now + 300 {
        return Ok(CommandVerdict::NotYetValid);
    }
    if guard.has_seen(&command.nonce) {
        return Ok(CommandVerdict::Replayed);
    }
    if command.action.is_weakening(current_timeout) {
        return Ok(CommandVerdict::WouldWeaken);
    }

    let vk = VerifyingKey::from_bytes(org_public_key)
        .map_err(|_| Error::Crypto("organization public key is malformed".into()))?;
    let sig_bytes: [u8; 64] = command
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("signature has the wrong length".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let payload = RemoteCommand::signing_payload(
        &command.vault_id,
        &command.action,
        &command.nonce,
        command.issued_at,
        command.expires_at,
    );

    Ok(match vk.verify(&payload, &signature) {
        Ok(()) => CommandVerdict::Accepted,
        Err(_) => CommandVerdict::BadSignature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SigningIdentity, [u8; 32], VaultId) {
        let id = SigningIdentity::from_seed([7u8; 32]);
        let pk = id.verifying_key();
        (id, pk, VaultId::from_bytes([1u8; 16]))
    }

    #[test]
    fn a_correctly_signed_command_is_accepted() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Lock, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Accepted
        );
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let (org, pk, vault) = setup();
        let guard = ReplayGuard::new();
        let good = org.issue(vault, CommandAction::Lock, 1000, 300);

        // Escalating the action must invalidate the signature.
        let mut escalated = good.clone();
        escalated.action = CommandAction::Destroy;
        assert_eq!(
            verify_command(&escalated, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );

        // Extending the window must too.
        let mut extended = good.clone();
        extended.expires_at += 100_000;
        assert_eq!(
            verify_command(&extended, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );

        // And so must changing the nonce.
        let mut renonced = good.clone();
        renonced.nonce[0] ^= 1;
        assert_eq!(
            verify_command(&renonced, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );
    }

    #[test]
    fn a_command_for_another_vault_is_refused() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let other = VaultId::from_bytes([2u8; 16]);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, other, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::WrongVault
        );
    }

    #[test]
    fn an_expired_command_is_refused_however_well_signed() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 2000, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Expired
        );
    }

    #[test]
    fn a_captured_command_cannot_be_replayed() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Lock, 1000, 3600);
        let mut guard = ReplayGuard::new();
        assert!(verify_command(&cmd, &pk, vault, 1010, 72 * 3600, &guard).unwrap().is_accepted());
        guard.remember(cmd.nonce);
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1020, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Replayed
        );
    }

    #[test]
    fn a_signed_command_cannot_weaken_a_vault() {
        // Someone holding the org key must not be able to quietly disarm every
        // endpoint by extending their deadlines.
        let (org, pk, vault) = setup();
        let guard = ReplayGuard::new();
        let loosen = org.issue(
            vault,
            CommandAction::TightenPolicy { timeout_seconds: 365 * 24 * 3600 },
            1000,
            300,
        );
        assert_eq!(
            verify_command(&loosen, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::WouldWeaken
        );

        // Tightening is permitted.
        let tighten =
            org.issue(vault, CommandAction::TightenPolicy { timeout_seconds: 3600 }, 1000, 300);
        assert!(verify_command(&tighten, &pk, vault, 1010, 72 * 3600, &guard)
            .unwrap()
            .is_accepted());
    }

    #[test]
    fn a_different_organisation_key_is_refused() {
        let (org, _, vault) = setup();
        let impostor = SigningIdentity::from_seed([8u8; 32]);
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &impostor.verifying_key(), vault, 1010, 72 * 3600, &guard)
                .unwrap(),
            CommandVerdict::BadSignature
        );
    }

    #[test]
    fn a_command_from_the_future_is_not_banked() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 100_000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1000, 72 * 3600, &guard).unwrap(),
            CommandVerdict::NotYetValid
        );
    }

    #[test]
    fn there_is_no_command_that_reads_vault_contents() {
        // The server must never be able to obtain plaintext. This is a
        // property of the action set, so it is asserted on the action set.
        for action in [
            CommandAction::Lock,
            CommandAction::RequireCheckIn,
            CommandAction::TightenPolicy { timeout_seconds: 60 },
            CommandAction::Destroy,
        ] {
            let l = action.label();
            assert!(!l.contains("READ") && !l.contains("EXPORT") && !l.contains("UNLOCK"), "{l}");
        }
    }
}
