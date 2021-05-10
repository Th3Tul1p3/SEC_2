use argon2::Config;
use hex;
use postgres::{Connection, TlsMode};
use sha3::{Digest, Sha3_256};
use validators;
use rand::prelude::*;

struct User {
    username: String,
    password: String,
    twofa: bool,
}

pub fn register(username: &str, password: &str, twofa: bool) -> bool {
    let mut is_valid = true;
    is_valid &= validators::is_username_valid(username);
    is_valid &= validators::is_password_valid(password);
    if !is_valid {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        return false;
    }

    let conn: Connection = Connection::connect(
        "postgresql://admin:S3c@localhost:5432/beautiful_db",
        TlsMode::None,
    )
    .unwrap();

    let mut hasher = Sha3_256::new();
    hasher.update(username.to_owned().as_bytes());

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    let result = hex::encode(hasher.finalize());
    let is_twofa_enable = twofa;
    println!("twofa {:?}", is_twofa_enable);
    let user = User {
        username: result,
        password: hash,
        twofa: true,
    };
    conn.execute(
        "INSERT INTO user_table (username, password, twofa) VALUES ($1, $2, $3)",
        &[&user.username, &user.password, &user.twofa],
    )
    .unwrap();

    is_valid
}
