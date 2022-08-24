#[cfg(test)]

mod jwt_test_support;

use jwt_cache::JwtCache;
use jsonwebtoken::{decode, get_current_timestamp, Validation, DecodingKey};
use jwt_test_support::{get_test_jwt, TestClaims};
use std::cell::Cell;

#[test]
fn instance_test() {
  JwtCache::new(|| {
    Some("".to_string())
  });
}

#[test]
fn refresh_jwt_test() {
  let jwt_data: (String, Vec<u8>) = get_test_jwt(true);

  let mut jwt_cache = JwtCache::new(|| {
    Some(jwt_data.0.clone())
  });

  assert_eq!(jwt_cache.jwt().unwrap(), jwt_data.0);
}

#[test]
fn expired_jwt_test() {
  let jwt_data: (String, Vec<u8>) = get_test_jwt(true);

  let mut jwt_cache = JwtCache::new(|| {
    Some(jwt_data.0.clone())
  });

  let mut validation = Validation::default();
  validation.insecure_disable_signature_validation();
  validation.validate_exp = false;

  let claims = decode::<TestClaims>(&jwt_cache.jwt().unwrap(), &DecodingKey::from_secret(&jwt_data.1), &validation);

  assert!(claims.unwrap().claims.exp < get_current_timestamp());
}

#[test]
fn current_jwt_test() {
  let jwt_data: (String, Vec<u8>) = get_test_jwt(false);

  let mut jwt_cache = JwtCache::new(|| {
    Some(jwt_data.0.clone())
  });

  let mut validation = Validation::default();
  validation.insecure_disable_signature_validation();

  let claims = decode::<TestClaims>(&jwt_cache.jwt().unwrap(), &DecodingKey::from_secret(&jwt_data.1), &validation);

  assert!(claims.unwrap().claims.exp >= get_current_timestamp());
}

#[test]
fn jwt_renew_test() {
  
  // Because we want to check t various points in the lifecycle.
  let mut validation = Validation::default();
  validation.insecure_disable_signature_validation();
  validation.validate_exp = false;

  let mut jwt_data: (String, Vec<u8>) = get_test_jwt(true);
  let first_jwt = jwt_data.0.clone();

  // Necessary to accomodate post-closure updates.
  let returned_jwt = Cell::new(first_jwt.as_str());

  let mut jwt_cache = JwtCache::new(|| {  
    Some(returned_jwt.get().to_string())
  });

  let mut jwt: String = jwt_cache.jwt().unwrap();
  let mut claims = decode::<TestClaims>(&jwt, &DecodingKey::from_secret(&jwt_data.1), &validation);

  assert_eq!(jwt, jwt_data.0);
  assert!(claims.unwrap().claims.exp < get_current_timestamp());

  
  jwt_data = get_test_jwt(false);
  let second_jwt = jwt_data.0.clone();

  // Make sure the JWTs aren't equal.
  assert_ne!(first_jwt, second_jwt);

  returned_jwt.set(second_jwt.as_str());

  jwt = jwt_cache.jwt().unwrap();
  claims = decode::<TestClaims>(&jwt, &DecodingKey::from_secret(&jwt_data.1), &validation);

  assert_eq!(jwt, jwt_data.0);
  assert!(claims.unwrap().claims.exp >= get_current_timestamp());
}