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

