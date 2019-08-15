// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// #![warn(missing_docs)]

#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

mod brain;
mod brain_prefix;
mod error;
mod extended;
mod keccak;
mod keypair;
mod password;
mod prefix;
mod random;
mod secret;
mod signature;

pub mod brain_recover;
pub mod crypto;
pub mod math;

pub use self::brain::Brain;
pub use self::brain_prefix::BrainPrefix;
pub use self::error::Error;
pub use self::extended::{
    Derivation, DerivationError, ExtendedKeyPair, ExtendedPublic, ExtendedSecret,
};
pub use self::keypair::{public_to_address, KeyPair};
pub use self::math::public_is_valid;
pub use self::password::Password;
pub use self::prefix::Prefix;
pub use self::random::Random;
pub use self::secret::Secret;
pub use self::signature::{recover, sign, verify_address, verify_public, Signature};
pub use parity_wordlist::Error as WordlistError;

use ethereum_types::H256;

pub use ethereum_types::{Address, Public};
pub type Message = H256;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

/// Uninstantiatable error type for infallible generators.
#[derive(Debug)]
pub enum Void {}

/// Generates new keypair.
pub trait Generator {
    type Error;

    /// Should be called to generate new keypair.
    fn generate(&mut self) -> Result<KeyPair, Self::Error>;
}
