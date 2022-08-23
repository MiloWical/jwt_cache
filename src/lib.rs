use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, Validation, DecodingKey};

struct JwtCache<'a, F>
  where F: Fn() -> Option<&'a String>
{
  jwt: Option<&'a String>,
  exp: u64,
  refresh_function: F,
  validation: Validation,
  decoding_key: DecodingKey
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
  exp: u64
}

impl<'a, F> JwtCache<'a, F>
  where F: Fn() -> Option<&'a String>
{
  fn refresh(&mut self) {
    self.jwt = (self.refresh_function)();

    let claims = decode::<JwtClaims>(&self.jwt.unwrap(), &self.decoding_key, &self.validation);

    let claims_unwrapped = &claims.as_ref().unwrap().claims;
    self.exp = claims.unwrap().claims.exp;
  }

  pub fn jwt(&self) -> Option<&'a String> {
    self.jwt
  }

  pub fn new(refresh_function: F) -> Self { 
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;

    let decoding_key = DecodingKey::from_secret(b"");
    
    Self {
      jwt: None,
      exp: 0,
      refresh_function,
      validation,
      decoding_key
    }
  }

  pub fn set_validation_and_decoding_key(&mut self, validation: Validation, decoding_key: DecodingKey) {
    self.set_validation(validation);

    self.decoding_key = decoding_key;
  }

  pub fn set_validation(&mut self, validation: Validation) {
    self.validation = validation;
  }
}

#[cfg(test)]
mod tests {

  use jsonwebtoken::{Validation, Algorithm, DecodingKey};
  use serde::{Serialize, Deserialize};
  use std::time::{SystemTime, UNIX_EPOCH};
  use super::JwtCache;

  #[derive(Debug, Serialize, Deserialize)]
  struct Claims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
    given_name: String,
    surname: String,
    email: String,
    role: Vec<String>
  }

  // "iss": "Online JWT Builder",
  //   "iat": 1660520523,
  //   "exp": 1660520525,
  //   "aud": "www.example.com",
  //   "sub": "jrocket@example.com",
  //   "GivenName": "Johnny",
  //   "Surname": "Rocket",
  //   "Email": "jrocket@example.com",
  //   "Role": [
  //       "Manager",
  //       "Project Administrator"
  //   ]

  #[test]
  fn insecure_check() {
    let expected_jwt: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2NjA1MjA1MjMsImV4cCI6MTY2MDUyMDUyNSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.1SVid882Q7Y9jxbS40mfmIGs42hmUPCTyqkFP6b9J3s".to_string();
    let expected_exp: u64 = 1660520525;

    let mut jwt_cache = JwtCache::new(|| {
      Some(&expected_jwt)
    });

    assert!(jwt_cache.jwt.is_none());

    jwt_cache.refresh();

    assert_eq!(jwt_cache.jwt.unwrap(), &expected_jwt);
    assert_eq!(jwt_cache.exp, expected_exp);
  }

  #[test]
  fn validation_check() {
    let expected_jwt: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2NjA1MjA1MjMsImV4cCI6MTY2MDUyMDUyNSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.1SVid882Q7Y9jxbS40mfmIGs42hmUPCTyqkFP6b9J3s".to_string();
    let decoding_key_string: &[u8] = b"qwertyuiopasdfghjklzxcvbnm123456";
    //let expected_exp: u64 =  SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expected_exp: u64 = 1660520525;

    let mut jwt_cache = JwtCache::new(|| {
      Some(&expected_jwt)
    });

    assert!(jwt_cache.jwt.is_none());

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // Because test code.
    let decoding_key = DecodingKey::from_secret(decoding_key_string);

    jwt_cache.set_validation_and_decoding_key(validation, decoding_key);

    jwt_cache.refresh();

    assert_eq!(jwt_cache.jwt.unwrap(), &expected_jwt);
    assert_eq!(jwt_cache.exp, expected_exp);
  }
}
