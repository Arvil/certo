use std::fmt::Display;

use serde::Serialize;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct DaysToExpiration(pub i64);

impl Display for DaysToExpiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_days_to_expiration_display() {
        let days = DaysToExpiration(30);
        assert_eq!(days.to_string(), "30");

        let zero_days = DaysToExpiration(0);
        assert_eq!(zero_days.to_string(), "0");

        let negative_days = DaysToExpiration(-5);
        assert_eq!(negative_days.to_string(), "-5");
    }

    #[test]
    fn test_days_to_expiration_serialization() {
        let days = DaysToExpiration(45);
        let json = serde_json::to_string(&days).unwrap();
        assert_eq!(json, "45");
    }

    #[test]
    fn test_days_to_expiration_ord() {
        let days_10 = DaysToExpiration(10);
        let days_30 = DaysToExpiration(30);
        let days_5 = DaysToExpiration(5);

        assert!(days_5 < days_10);
        assert!(days_10 < days_30);
        assert!(days_30 > days_5);
        assert!(days_10 == DaysToExpiration(10));
    }

    #[test]
    fn test_days_to_expiration_eq() {
        let days_1 = DaysToExpiration(30);
        let days_2 = DaysToExpiration(30);
        let days_3 = DaysToExpiration(20);

        assert_eq!(days_1, days_2);
        assert_ne!(days_1, days_3);
    }
}
