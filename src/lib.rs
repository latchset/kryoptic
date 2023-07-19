#[no_mangle]
pub extern "C" fn test() -> bool {
    true
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = test();
        assert_eq!(result, true);
    }
}
