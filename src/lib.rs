struct Jwt<'a, F>
  where F: Fn() -> Option<&'a String>
{
  jwt: Option<&'a String>,
  exp: u64,
  refresh_function: F
}

trait JwtCache {
  fn refresh(&mut self);
}

impl<'a, F> JwtCache for Jwt<'a, F>
  where F: Fn() -> Option<&'a String>
{
  fn refresh(&mut self) {
    self.jwt = (self.refresh_function)();
  }
}

#[cfg(test)]
mod tests {

  use std::time::{SystemTime, UNIX_EPOCH};
  use super::{Jwt, JwtCache};

  #[test]
  fn it_works() {
      let result = 2 + 2;
      assert_eq!(result, 4);
  }

  #[test]
  fn instance_check() {
    let expected_jwt: String = "Hello, World!".to_string();
    let expected_exp: u64 =  SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let mut jwt_cache = Jwt {
      jwt: None,
      exp: expected_exp,
      refresh_function: || Some(&expected_jwt)
    };

    assert!(jwt_cache.jwt.is_none());

    jwt_cache.refresh();

    assert_eq!(jwt_cache.jwt.unwrap(), &expected_jwt);
    assert_eq!(jwt_cache.exp, expected_exp);
  }
}
