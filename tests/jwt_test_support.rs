use rand::RngCore;
use jsonwebtoken::{encode, get_current_timestamp, EncodingKey, Header, Algorithm};
use serde::{Deserialize, Serialize};

pub fn get_test_jwt(expired: bool) -> (String, Vec<u8>) {
  let mut raw_key = vec![0u8; 32];
  rand::thread_rng().fill_bytes(&mut raw_key);

  let exp: u64;

  if expired {
    exp = get_current_timestamp() - 1;
  }
  else {
    exp = get_current_timestamp() + 60;
  }

  let claims = TestClaims {
    exp,
    sub: "milowical".to_string(),
    email: "milowical@example.com".to_string()
  };

  let jwt = encode(&Header::new(Algorithm::HS512), &claims, &EncodingKey::from_secret(&raw_key));

  (jwt.unwrap(), raw_key)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestClaims {
  pub exp: u64,
  pub sub: String,
  pub email: String
}