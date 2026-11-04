//! Transaction nonces handed out per signing DID.
//!
//! The node accepts a transaction under a nonce in `base + 1 ..= base + 24` that it hasn't used,
//! and `base` advances only over used nonces with no gap below them. Reading `base + 1` for every
//! write gives two writes in flight the same nonce, and a nonce taken and never used (its
//! transaction refused at CheckTx or dropped from the mempool) blocks the window until something
//! uses it.
//!
//! A [`NonceTracker`] keeps, per DID, the nonces it has handed out that haven't landed (each with
//! when it was handed out) and the nonces the chain reports used above the base. It hands out the
//! lowest nonce in the window that is neither used nor handed out within the last 120 s (the
//! node holds a pending transaction's nonce for 3 blocks or 120 s, whichever ends first), under a
//! lock, so two concurrent writes can't take the same one. A submission refused at CheckTx gives
//! its nonce back unless the node's refusal of that nonce says it is held by a pending
//! transaction, already used, at or below the base, or spent ([`refusal_outcome`]).
//!
//! Every write path of [`crate::consensus::ConsensusClient`] (and so of the file and key-grant
//! operations) takes its nonce here.

use crate::errors::{Result, WillowError};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many nonces above the base the node accepts.
pub const NONCE_WINDOW: u64 = 24;

/// How long a nonce handed out, and not seen to land, stays taken.
pub const NONCE_HOLD: Duration = Duration::from_secs(120);

/// An account's nonce state as the chain reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountNonceState {
    /// Every nonce at or below the base is used.
    pub base: u64,
    /// Bit `i` set: `base + 1 + i` is used (24 bits). 0 when only the base is known.
    pub used: u32,
}

impl AccountNonceState {
    /// The value of the ABCI query `/store/account_nonce_state/{did}`: the base as a big-endian
    /// u64, then 3 bytes in which bit `i % 8` of byte `i / 8` marks `base + 1 + i` used. 8 bytes
    /// is the base alone (`/store/account_nonce/{did}`); none is an account with no transaction
    /// yet.
    pub fn from_bytes(value: &[u8]) -> Result<Self> {
        match value.len() {
            0 => Ok(Self::default()),
            8 | 11 => {
                let base = u64::from_be_bytes(value[..8].try_into().expect("8 bytes"));
                let used = value[8..]
                    .iter()
                    .enumerate()
                    .fold(0u32, |bits, (i, b)| bits | (*b as u32) << (8 * i));
                Ok(Self { base, used })
            }
            n => Err(WillowError::Validation(format!(
                "an account nonce state of {n} bytes; the node answers 8 or 11"
            ))),
        }
    }

    /// Whether the chain shows `nonce` used: at or below the base, or its bit set.
    pub fn is_used(&self, nonce: u64) -> bool {
        if nonce <= self.base {
            return true;
        }
        let offset = nonce - self.base - 1;
        offset < NONCE_WINDOW && self.used & (1 << offset) != 0
    }

    /// The nonces above the base the chain shows used.
    fn used_nonces(&self) -> impl Iterator<Item = u64> + '_ {
        (0..NONCE_WINDOW)
            .filter(move |i| self.used & (1 << i) != 0)
            .map(move |i| self.base.saturating_add(1 + i))
    }
}

/// What a submission left its nonce as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOutcome {
    /// CheckTx accepted it, or the mempool already holds these exact bytes: taken until the
    /// chain shows it used or its hold lapses.
    Accepted,
    /// Refused without the nonce being held or used: free again.
    Free,
    /// Refused because a pending transaction holds the nonce: taken for a hold from now.
    Held,
    /// Refused because the node has used or spent the nonce: no transaction under it can run.
    Used,
    /// Unknown whether it reached the node (a network or RPC error): taken for a hold from now.
    Unknown,
}

/// The outcome of a CheckTx refusal whose log is `log`, for a transaction signed under `nonce`.
///
/// The nonce is given back ([`NonceOutcome::Free`]) unless the log is the node's own refusal of
/// this nonce: it starts `Nonce <nonce> of <did> is held by a pending transaction`
/// ([`NonceOutcome::Held`]), or `Invalid nonce: <nonce> already used` or `Invalid nonce: <nonce>
/// <= base nonce`, or ends `(nonce <nonce> spent)` ([`NonceOutcome::Used`]). Only those forms
/// count: a log that merely quotes them (a signature mismatch quotes the whole expected message,
/// user data included) says nothing about the nonce.
pub fn refusal_outcome(log: &str, nonce: u64) -> NonceOutcome {
    let log = log.trim();
    if let Some(rest) = log.strip_prefix(&format!("Nonce {nonce} of ")) {
        let after_signer = rest.split_once(char::is_whitespace).map(|(_, r)| r);
        if after_signer.is_some_and(|r| r.starts_with("is held by a pending transaction")) {
            return NonceOutcome::Held;
        }
    }
    if log.starts_with(&format!("Invalid nonce: {nonce} already used"))
        || log.starts_with(&format!("Invalid nonce: {nonce} <= base nonce"))
        || log.ends_with(&format!("(nonce {nonce} spent)"))
    {
        return NonceOutcome::Used;
    }
    NonceOutcome::Free
}

/// The clock a [`NonceTracker`] reads holds against.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Default)]
struct Account {
    base: u64,
    used: BTreeSet<u64>,
    handed: HashMap<u64, Instant>,
}

/// The nonces one client has handed out, per signing DID. Thread-safe; nothing in it awaits.
pub struct NonceTracker {
    clock: Clock,
    accounts: Mutex<HashMap<String, Account>>,
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NonceTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceTracker").finish_non_exhaustive()
    }
}

impl NonceTracker {
    /// A tracker on the system's monotonic clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }

    /// A tracker on `clock` (tests pass one they advance).
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            clock,
            accounts: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Account>> {
        self.accounts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Merge `state` into what is known of `account` (the highest base seen; a nonce once used
    /// stays used), then drop what the base passed and the holds that lapsed.
    fn refresh(account: &mut Account, state: Option<&AccountNonceState>, now: Instant) {
        if let Some(state) = state {
            account.used.extend(state.used_nonces());
            account.base = account.base.max(state.base);
        }
        let base = account.base;
        account.used.retain(|n| *n > base);
        let used = &account.used;
        account
            .handed
            .retain(|n, at| *n > base && !used.contains(n) && now.duration_since(*at) < NONCE_HOLD);
    }

    /// Hand out the lowest nonce in `did`'s window that isn't used or handed out within the hold,
    /// given the state the chain just reported. [`WillowError::NonceWindowFull`] when every one
    /// is: never a nonce past `base + 24`.
    pub fn take(&self, did: &str, state: AccountNonceState) -> Result<u64> {
        let now = (self.clock)();
        let mut accounts = self.lock();
        let account = accounts.entry(did.to_string()).or_default();
        Self::refresh(account, Some(&state), now);
        let base = account.base;
        let last = base.saturating_add(NONCE_WINDOW);
        for nonce in base.saturating_add(1)..=last {
            if !account.used.contains(&nonce) && !account.handed.contains_key(&nonce) {
                account.handed.insert(nonce, now);
                return Ok(nonce);
            }
        }
        Err(WillowError::NonceWindowFull(format!(
            "every nonce the node accepts for {did} ({}..={last}) is used or held by a write in \
             flight; send more once earlier writes land",
            base.saturating_add(1)
        )))
    }

    /// Mark `nonce` taken from now, for a transaction signed under a nonce the caller chose or
    /// one whose submission may still land.
    pub fn hold(&self, did: &str, nonce: u64) {
        let now = (self.clock)();
        let mut accounts = self.lock();
        let account = accounts.entry(did.to_string()).or_default();
        Self::refresh(account, None, now);
        if nonce > account.base && !account.used.contains(&nonce) {
            account.handed.insert(nonce, now);
        }
    }

    /// Record what a submission left `nonce` as.
    pub fn settle(&self, did: &str, nonce: u64, outcome: NonceOutcome) {
        match outcome {
            NonceOutcome::Accepted | NonceOutcome::Held | NonceOutcome::Unknown => {
                self.hold(did, nonce)
            }
            NonceOutcome::Free => self.release(did, nonce),
            NonceOutcome::Used => {
                let mut accounts = self.lock();
                let account = accounts.entry(did.to_string()).or_default();
                account.handed.remove(&nonce);
                if nonce > account.base {
                    account.used.insert(nonce);
                }
            }
        }
    }

    /// Give back `nonce`, handed out for a transaction that was never sent or was refused
    /// without using it.
    pub fn release(&self, did: &str, nonce: u64) {
        if let Some(account) = self.lock().get_mut(did) {
            account.handed.remove(&nonce);
        }
    }

    /// Whether `nonce` of `did` is handed out and its hold hasn't lapsed.
    pub fn is_held(&self, did: &str, nonce: u64) -> bool {
        let now = (self.clock)();
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(did) else {
            return false;
        };
        Self::refresh(account, None, now);
        account.handed.contains_key(&nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock the test advances.
    fn clock() -> (Clock, Arc<Mutex<Duration>>) {
        let start = Instant::now();
        let offset = Arc::new(Mutex::new(Duration::ZERO));
        let read = offset.clone();
        (Arc::new(move || start + *read.lock().unwrap()), offset)
    }

    fn state(base: u64, used: &[u64]) -> AccountNonceState {
        AccountNonceState {
            base,
            used: used.iter().fold(0, |bits, n| bits | 1 << (n - base - 1)),
        }
    }

    const DID: &str = "did:willow:a";

    #[test]
    fn the_nonce_state_parses_as_the_node_answers_it() {
        assert_eq!(
            AccountNonceState::from_bytes(&[]).unwrap(),
            AccountNonceState::default()
        );
        let base_only = AccountNonceState::from_bytes(&7u64.to_be_bytes()).unwrap();
        assert_eq!(base_only, AccountNonceState { base: 7, used: 0 });
        let mut value = 7u64.to_be_bytes().to_vec();
        // bit 0 of byte 0 is base + 1; bit 1 of byte 2 is base + 18.
        value.extend([0b0000_0001, 0, 0b0000_0010]);
        let s = AccountNonceState::from_bytes(&value).unwrap();
        assert_eq!(s.used_nonces().collect::<Vec<_>>(), vec![8, 25]);
        assert!(s.is_used(7) && s.is_used(8) && s.is_used(25));
        assert!(!s.is_used(9) && !s.is_used(31) && !s.is_used(32));
        assert!(AccountNonceState::from_bytes(&[0; 9]).is_err());
    }

    #[test]
    fn concurrent_writes_take_distinct_nonces_skipping_used_ones() {
        let tracker = NonceTracker::new();
        let s = state(10, &[11, 13]);
        assert_eq!(tracker.take(DID, s).unwrap(), 12);
        assert_eq!(tracker.take(DID, s).unwrap(), 14);
        assert_eq!(tracker.take(DID, s).unwrap(), 15);
        // Another DID has its own window.
        assert_eq!(tracker.take("did:willow:b", s).unwrap(), 12);
    }

    #[test]
    fn a_full_window_is_an_error_and_never_a_nonce_past_it() {
        let tracker = NonceTracker::new();
        let s = state(100, &[]);
        let taken: Vec<u64> = (0..24).map(|_| tracker.take(DID, s).unwrap()).collect();
        assert_eq!(taken, (101..=124).collect::<Vec<_>>());
        let err = tracker.take(DID, s).unwrap_err();
        assert!(matches!(err, WillowError::NonceWindowFull(_)), "{err}");
        // Once the base advances over landed ones, more are free.
        assert_eq!(tracker.take(DID, state(102, &[])).unwrap(), 125);
    }

    #[test]
    fn a_hold_lapses_after_120_seconds() {
        let (clock, offset) = clock();
        let tracker = NonceTracker::with_clock(clock);
        let s = state(0, &[]);
        assert_eq!(tracker.take(DID, s).unwrap(), 1);
        *offset.lock().unwrap() = Duration::from_secs(119);
        assert_eq!(tracker.take(DID, s).unwrap(), 2);
        assert!(tracker.is_held(DID, 1));
        *offset.lock().unwrap() = Duration::from_secs(120);
        assert!(!tracker.is_held(DID, 1));
        // 1 was handed out 120 s ago and hasn't landed: free again. 2 is still held.
        assert_eq!(tracker.take(DID, s).unwrap(), 1);
        assert_eq!(tracker.take(DID, s).unwrap(), 3);
    }

    #[test]
    fn a_refusal_gives_the_nonce_back_unless_it_says_the_nonce_is_taken() {
        let tracker = NonceTracker::new();
        let s = state(0, &[]);
        let n = tracker.take(DID, s).unwrap();
        tracker.settle(DID, n, refusal_outcome("Insufficient balance", n));
        assert_eq!(tracker.take(DID, s).unwrap(), n, "a plain refusal frees it");

        tracker.settle(
            DID,
            n,
            refusal_outcome(
                &format!("Nonce {n} of {DID} is held by a pending transaction; sign this one with another nonce"),
                n,
            ),
        );
        assert_eq!(tracker.take(DID, s).unwrap(), n + 1, "held stays taken");

        let m = n + 1;
        tracker.settle(
            DID,
            m,
            refusal_outcome(&format!("Invalid nonce: {m} already used (replay)"), m),
        );
        assert_eq!(tracker.take(DID, s).unwrap(), m + 1, "used stays taken");
        // A used nonce stays out of the window even after its hold would lapse.
        tracker.release(DID, m);
        assert_eq!(tracker.take(DID, s).unwrap(), m + 2);
    }

    #[test]
    fn only_the_nodes_own_refusal_of_this_nonce_keeps_it() {
        let n = 7;
        for (log, outcome) in [
            (
                "Nonce 7 of did:willow:a is held by a pending transaction; sign this one with another nonce",
                NonceOutcome::Held,
            ),
            ("Invalid nonce: 7 already used (replay)", NonceOutcome::Used),
            ("Invalid nonce: 7 <= base nonce 9", NonceOutcome::Used),
            ("Subgrove not found (nonce 7 spent)", NonceOutcome::Used),
            // Another nonce's refusal says nothing about this one.
            ("Invalid nonce: 70 already used (replay)", NonceOutcome::Free),
            ("Invalid nonce: 8 <= base nonce 9", NonceOutcome::Free),
            (
                "Nonce 17 of did:willow:a is held by a pending transaction",
                NonceOutcome::Free,
            ),
            ("Subgrove not found (nonce 17 spent)", NonceOutcome::Free),
            // A log quoting the forms (a signature mismatch quotes the signed message) is not one.
            (
                "Signature mismatch: Expected message to sign: \"Invalid nonce: 7 already used\"",
                NonceOutcome::Free,
            ),
            (
                "Invalid nonce: 7 is too far ahead (base=0, max=24)",
                NonceOutcome::Free,
            ),
        ] {
            assert_eq!(refusal_outcome(log, n), outcome, "{log}");
        }
    }

    #[test]
    fn a_lagging_answer_cannot_hand_out_a_used_nonce() {
        let tracker = NonceTracker::new();
        assert_eq!(tracker.take(DID, state(5, &[6])).unwrap(), 7);
        // An older answer (base 3) can't bring back 4..=6.
        assert_eq!(tracker.take(DID, state(3, &[])).unwrap(), 8);
    }

    #[test]
    fn an_accepted_or_unknown_submission_holds_its_nonce_from_now() {
        let (clock, offset) = clock();
        let tracker = NonceTracker::with_clock(clock);
        let s = state(0, &[]);
        let n = tracker.take(DID, s).unwrap();
        *offset.lock().unwrap() = Duration::from_secs(100);
        tracker.settle(DID, n, NonceOutcome::Unknown);
        *offset.lock().unwrap() = Duration::from_secs(200);
        assert!(
            tracker.is_held(DID, n),
            "held 120 s from the unknown outcome"
        );
        *offset.lock().unwrap() = Duration::from_secs(220);
        assert!(!tracker.is_held(DID, n));
        // Once the chain shows it used, it is never handed out again, nor held.
        assert_eq!(tracker.take(DID, state(n, &[])).unwrap(), n + 1);
        tracker.hold(DID, n);
        assert!(!tracker.is_held(DID, n));
    }
}
