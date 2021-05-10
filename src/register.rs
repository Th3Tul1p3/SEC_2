use validators;

pub fn register(username: &str, password: &str) -> bool {
    let mut is_valid = true;
    is_valid &= validators::is_username_valid(username);
    is_valid &= validators::is_password_valid(password);
    is_valid
}
