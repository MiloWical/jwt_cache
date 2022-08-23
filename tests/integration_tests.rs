#[cfg(test)]
mod integration_tests {
  use jwt_cache::JwtCache;
  use serde::{Deserialize, Serialize};
  use jsonwebtoken::{encode, decode, get_current_timestamp, Validation, EncodingKey, DecodingKey, Header, Algorithm};
  use rand::RngCore;

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

  fn get_test_jwt(expired: bool) -> (String, Vec<u8>) {
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
  struct TestClaims {
    exp: u64,
    sub: String,
    email: String
  }
}