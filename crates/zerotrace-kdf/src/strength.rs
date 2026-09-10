//! How good a password has to be.
//!
//! Length is what matters and nothing else is required. Forcing a symbol and a
//! digit produces `Password1!`, which is worse than four unrelated words and
//! harder to remember. The rule here is therefore a length floor, with a
//! passphrase encouraged rather than demanded.
//!
//! Enforced when a vault is created, because that is the only moment a
//! password can be chosen. An existing vault cannot be made to have a better
//! one retroactively.

use zerotrace_core::{Error, Result};

/// Shortest password accepted for a new vault.
///
/// Fifteen characters, which four short words and their separators reach
/// comfortably, and which a single word does not.
pub const MIN_LENGTH: usize = 15;

/// A word count at which a dash-separated phrase is worth calling strong.
pub const PASSPHRASE_WORDS: usize = 4;

/// What was made of a proposed password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strength {
    /// Below the floor. Refused.
    TooShort { have: usize, need: usize },
    /// Long enough, but a single run of characters.
    Acceptable,
    /// A phrase of several separated words.
    Strong { words: usize },
}

impl Strength {
    pub fn is_acceptable(&self) -> bool {
        !matches!(self, Strength::TooShort { .. })
    }

    /// A sentence to show the person choosing.
    pub fn advice(&self) -> String {
        match self {
            Strength::TooShort { have, need } => format!(
                "Too short: {have} characters, and {need} are needed. Four or five \
                 unrelated words joined by dashes is the easiest way to get there, for \
                 example correct-horse-battery-staple."
            ),
            Strength::Acceptable => "Long enough. A phrase of several unrelated words \
                 joined by dashes would be easier to remember and harder to guess."
                .to_string(),
            Strength::Strong { words } => format!(
                "A phrase of {words} words. Easy to remember, and long enough that \
                 guessing it is not worth attempting."
            ),
        }
    }
}

/// Counts the words in a separated phrase.
fn word_count(password: &str) -> usize {
    password
        .split(['-', ' ', '_', '.'])
        .filter(|w| w.len() >= 2)
        .count()
}

/// Assesses a proposed password.
pub fn assess(password: &str) -> Strength {
    let have = password.chars().count();
    if have < MIN_LENGTH {
        return Strength::TooShort { have, need: MIN_LENGTH };
    }
    let words = word_count(password);
    if words >= PASSPHRASE_WORDS {
        Strength::Strong { words }
    } else {
        Strength::Acceptable
    }
}

/// Refuses a password that does not meet the floor.
///
/// Called when a vault is created. Opening an existing vault never applies
/// this: a vault made under an older rule must still open.
pub fn require_acceptable(password: &str) -> Result<()> {
    let s = assess(password);
    if s.is_acceptable() {
        Ok(())
    } else {
        Err(Error::Other(s.advice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passwords_are_refused_however_complex() {
        // The reason complexity rules are not used: this passes every symbol
        // and digit rule ever written and is still terrible.
        for p in ["P@ssw0rd!", "x", "", "Tr0ub4dor&3"] {
            assert!(!assess(p).is_acceptable(), "{p} was accepted");
            assert!(require_acceptable(p).is_err());
        }
    }

    #[test]
    fn a_long_passphrase_is_strong() {
        match assess("correct-horse-battery-staple") {
            Strength::Strong { words } => assert_eq!(words, 4),
            other => panic!("expected strong, got {other:?}"),
        }
        assert!(require_acceptable("correct-horse-battery-staple").is_ok());
    }

    #[test]
    fn spaces_and_underscores_count_as_separators() {
        assert!(matches!(assess("correct horse battery staple"), Strength::Strong { .. }));
        assert!(matches!(assess("correct_horse_battery_staple"), Strength::Strong { .. }));
    }

    #[test]
    fn a_long_single_word_is_acceptable_but_not_strong() {
        assert_eq!(assess("aaaaaaaaaaaaaaaaaaaa"), Strength::Acceptable);
        assert!(require_acceptable("aaaaaaaaaaaaaaaaaaaa").is_ok());
    }

    #[test]
    fn the_boundary_is_where_it_says_it_is() {
        let just_short: String = "a".repeat(MIN_LENGTH - 1);
        let just_long: String = "a".repeat(MIN_LENGTH);
        assert!(!assess(&just_short).is_acceptable());
        assert!(assess(&just_long).is_acceptable());
    }

    #[test]
    fn advice_names_the_shortfall() {
        let a = assess("short").advice();
        assert!(a.contains("15"), "{a}");
        assert!(a.contains("dashes"), "{a}");
    }
}
