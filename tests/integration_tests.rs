mod common;

#[test]
fn test_cert_test_json_serialization() {
    let cert_test = common::CertTest {
        hostname: "example.com",
        result: Ok(common::DaysToExpiration(30)),
    };

    let json_value = serde_json::to_value(&cert_test).unwrap();
    assert_eq!(json_value["hostname"], "example.com");
    assert_eq!(json_value["success"], true);
    assert_eq!(json_value["remainingDays"], 30);
    assert!(json_value["message"].as_str().unwrap().contains("30 days remaining"));
}

#[test]
fn test_cert_test_error_json_serialization() {
    let cert_test = common::CertTest {
        hostname: "example.com",
        result: Err(common::Error::ConnectionFailure {
            hostname: "example.com".to_string(),
            details: "Connection timeout".to_string(),
        }),
    };

    let json_value = serde_json::to_value(&cert_test).unwrap();
    assert_eq!(json_value["hostname"], "example.com");
    assert_eq!(json_value["success"], false);
    assert!(json_value["message"].as_str().unwrap().contains("Connection timeout"));
    assert!(json_value["remainingDays"].is_null());
}

#[test]
fn test_certificate_expiration_threshold_logic() {
    // Test the expiration logic with different thresholds
    let mock_cert = common::create_mock_certificate_with_expiration_days(10);

    // Test with threshold higher than remaining days (should fail)
    let result_high_threshold = common::test_expiration_logic(&mock_cert, 15);
    assert!(result_high_threshold.is_err());

    // Test with threshold lower than remaining days (should pass)
    let result_low_threshold = common::test_expiration_logic(&mock_cert, 5);
    assert!(result_low_threshold.is_ok());

    if let Ok(common::DaysToExpiration(days)) = result_low_threshold {
        assert_eq!(days, 10);
    }
}

#[test]
fn test_certificate_expiration_exact_threshold() {
    // Test when remaining days exactly equals threshold
    let mock_cert = common::create_mock_certificate_with_expiration_days(10);

    // Test with threshold exactly equal to remaining days (should fail)
    let result_exact_threshold = common::test_expiration_logic(&mock_cert, 10);
    assert!(result_exact_threshold.is_err());

    // Test with threshold one day less than remaining days (should pass)
    let result_one_day_less = common::test_expiration_logic(&mock_cert, 9);
    assert!(result_one_day_less.is_ok());
}

#[test]
fn test_error_variants_serialization() {
    // Test serialization of different error variants
    let error_cases = vec![
        common::Error::InvalidHostname {
            hostname: "bad hostname".to_string(),
            details: "contains spaces".to_string(),
        },
        common::Error::ConnectionFailure {
            hostname: "example.com".to_string(),
            details: "timeout".to_string(),
        },
        common::Error::InvalidCertificate {
            why: "malformed certificate".to_string(),
        },
        common::Error::AlmostExpiredCertificate {
            days_to_expiration: 2,
            max_days_to_expiration: 30,
        },
        common::Error::NoCertificate,
    ];

    for error in error_cases {
        let cert_test = common::CertTest {
            hostname: "test.example.com",
            result: Err(error),
        };

        let json = serde_json::to_string(&cert_test);
        assert!(json.is_ok(), "Failed to serialize error: {:?}", cert_test.result);
    }
}

#[test]
fn test_certificate_with_zero_days_remaining() {
    let mock_cert = common::create_mock_certificate_with_expiration_days(0);

    // Test with threshold of 1 day (should fail)
    let result = common::test_expiration_logic(&mock_cert, 1);
    assert!(result.is_err());

    if let Err(common::Error::AlmostExpiredCertificate { days_to_expiration, max_days_to_expiration }) = result {
        assert_eq!(days_to_expiration, 0);
        assert_eq!(max_days_to_expiration, 1);
    } else {
        panic!("Expected AlmostExpiredCertificate error");
    }
}

#[test]
fn test_certificate_with_negative_days_remaining() {
    let mock_cert = common::create_mock_certificate_with_expiration_days(-5);

    // Test with any threshold (should fail)
    let result = common::test_expiration_logic(&mock_cert, 30);
    assert!(result.is_err());

    if let Err(common::Error::AlmostExpiredCertificate { days_to_expiration, max_days_to_expiration }) = result {
        assert_eq!(days_to_expiration, -5);
        assert_eq!(max_days_to_expiration, 30);
    } else {
        panic!("Expected AlmostExpiredCertificate error");
    }
}

#[test]
fn test_certificate_with_very_large_expiration() {
    let mock_cert = common::create_mock_certificate_with_expiration_days(3650); // ~10 years

    // Test with normal threshold (should pass)
    let result = common::test_expiration_logic(&mock_cert, 30);
    assert!(result.is_ok());

    if let Ok(common::DaysToExpiration(days)) = result {
        assert_eq!(days, 3650);
    }
}

#[test]
fn test_json_structure_completeness() {
    let cert_test = common::CertTest {
        hostname: "example.com",
        result: Ok(common::DaysToExpiration(45)),
    };

    let json_value = serde_json::to_value(&cert_test).unwrap();
    let obj = json_value.as_object().unwrap();

    // Check all expected fields are present
    assert!(obj.contains_key("hostname"));
    assert!(obj.contains_key("success"));
    assert!(obj.contains_key("message"));
    assert!(obj.contains_key("remainingDays"));

    // Check field types
    assert!(obj["hostname"].is_string());
    assert!(obj["success"].is_boolean());
    assert!(obj["message"].is_string());
    assert!(obj["remainingDays"].is_number());
}