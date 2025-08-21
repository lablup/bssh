// Handler is not needed for async-ssh2-tokio
// This file is kept for compatibility with the module structure

#[derive(Clone)]
pub struct BsshHandler {
    pub host: String,
}

impl BsshHandler {
    pub fn new(host: String) -> Self {
        Self { host }
    }
}
