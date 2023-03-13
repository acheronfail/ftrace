use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// Structs

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallInfo {
    pub id: u64,
    pub abi: String,
    pub name: String,
    pub impl_name: Option<String>,
    #[serde(flatten)]
    pub inner: SyscallInfoInner,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SyscallInfoInner {
    #[serde(rename = "signatures")]
    Signatures(Vec<SyscallSignature>),
    #[serde(rename = "skipped")]
    Skipped(SkipReason),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SkipReason {
    Unimplemented,
    Deprecated,
    Parameterless,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallSignature {
    pub key: String,
    pub matches: Vec<SyscallSignatureMatch>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallSignatureMatch {
    pub path: PathBuf,
    pub text: String,
    pub offset: usize,
    pub params: Vec<SyscallSignatureParam>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallSignatureParam {
    pub name: String,
    pub r#type: String,
}

// Impls

impl SyscallInfo {
    pub fn param_types(&self) -> Option<Vec<Vec<String>>> {
        match self.inner {
            SyscallInfoInner::Skipped(_) => None,
            SyscallInfoInner::Signatures(ref sigs) => Some(
                sigs.iter()
                    // TODO: this just grabs the first signature, but we should return both and check which one matches best
                    .map(|s| {
                        s.matches[0]
                            .params
                            .iter()
                            .map(|p| p.r#type.clone())
                            .collect()
                    })
                    .collect(),
            ),
        }
    }
}
