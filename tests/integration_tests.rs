#[cfg(test)]

mod jwt_support;

use jwt_cache::JwtCache;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, get_current_timestamp, Validation, EncodingKey, DecodingKey, Header, Algorithm};
use jwt_support::{get_test_jwt};

#[test]
fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
}

#[test]
fn instance_test() {
  let jwt = "".to_string();

  JwtCache::new(|| {
    Some(&jwt)
  });
}

#[test]
fn refresh_jwt_test() {
  let jwt_data: (String, Vec<u8>) = get_test_jwt(true);

  let mut jwt_cache = JwtCache::new(|| {
    Some(&jwt_data.0)
  });

  assert_eq!(jwt_cache.jwt().unwrap(), &jwt_data.0);
}