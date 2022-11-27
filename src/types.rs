use std::fmt::Display;

use serde::Serialize;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct DaysToExpiration(pub i64);

impl Display for DaysToExpiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
