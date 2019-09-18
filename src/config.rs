use crate::crypto::*;
use crate::errors::*;

use bincode;

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub provider_kp: SignKeyPair,
}

impl State {
    pub fn new() -> Self {
        let provider_kp = SignKeyPair::new();
        State { provider_kp }
    }
}
