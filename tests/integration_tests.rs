#[cfg(test)]
mod integration_tests {
  use jwt_cache::JwtCache;

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
}