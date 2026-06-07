pub fn runtime_ci_value() -> i32 {
    2 + 2
}

#[cfg(test)]
mod tests {
    use super::runtime_ci_value;

    #[test]
    fn runtime_ci_smoke() {
        assert_eq!(runtime_ci_value(), 4);
    }
}
