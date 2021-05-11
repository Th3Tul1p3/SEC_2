use argon2::Config;
use google_authenticator::GoogleAuthenticator;
use hex;
use postgres::{Connection, TlsMode};
use rand::prelude::*;
use sha3::{Digest, Sha3_256};
use std::process;
use validators;

struct User {
    username: String,
    password: String,
    twofa: bool,
    secret: String,
}

pub fn register(username: &str, password: &str, twofa: bool) {
    let mut is_valid = true;

    // vérification de la validité des arguments
    is_valid &= validators::is_username_valid(username);
    is_valid &= validators::is_password_valid(password);
    if !is_valid {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        return;
    }

    // connexion à la base de données
    let conn = match Connection::connect(
        "postgresql://admin:S3c@localhost:5432/beautiful_db",
        TlsMode::None,
    ) {
        Ok(connection) => connection,
        Err(_) => {
            println!("La base de donnée n'est pas joignable...");
            process::exit(0x0100)
        }
    };

    //initialisations de sha3 pour stocker le nom d'utilisateur
    let mut hasher = Sha3_256::new();
    hasher.update(username.to_owned().as_bytes());

    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();

    let auth = GoogleAuthenticator::new();

    let user = User {
        username: hex::encode(hasher.finalize()),
        password: hash,
        twofa,
        secret: auth.create_secret(32),
    };

    let rows = &conn
        .query(
            "SELECT secret FROM user_table WHERE username = $1",
            &[&user.username],
        )
        .unwrap();

    if rows.len() > 0 {
        println!("Cet utilisateur existe déjà. Si vous avez oublié votre mot de passe utilisé l'option -p");
        return;
    }

    conn.execute(
        "INSERT INTO user_table (username, password, twofa, secret) VALUES ($1, $2, $3, $4)",
        &[&user.username, &user.password, &user.twofa, &user.secret],
    )
    .unwrap();
}
