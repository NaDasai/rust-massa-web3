pub const MAX_GAS_CALL: u64 = 4294167295;
pub const MIN_GAS_CALL: u64 = 2100000;
pub const MAX_GAS_DEPLOYMENT: u64 = 3980167295;
pub const PERIOD_TO_LIVE_DEFAULT: u64 = 9;
pub const PERIOD_TO_LIVE_MAX: u64 = 9;
pub const PERIOD_TO_LIVE_MIN: u64 = 1;

pub enum PublicGRPCURL {
    Mainnet,
    Buildnet,
}

impl PublicGRPCURL {
    pub fn url(&self) -> &'static str {
        match self {
            PublicGRPCURL::Mainnet => "grpc://mainnet.massa.net:33037",
            PublicGRPCURL::Buildnet => "grpc://buildnet.massa.net:33037",
        }
    }
}
