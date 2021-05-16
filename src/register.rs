use argon2::Config;
use google_authenticator::GoogleAuthenticator;
use hex;
use postgres::Connection;
use rand::prelude::*;
use sha3::{Digest, Sha3_256};
use std::io;

struct User {
    username: String,
    password: String,
    twofa: bool,
    secret: String,
}

pub fn register(
    username: &str,
    password: &str,
    twofa: bool,
    stdout: &mut dyn io::Write,
    conn: &Connection,
) {
    //initialisations de sha3 pour stocker le nom d'utilisateur
    let mut hasher = Sha3_256::new();
    hasher.update(username.to_owned().as_bytes());

    // génération du sel pour argon2
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    // configuration argon2
    let config = Config::default();

    // configuration google authenticator
    let auth = GoogleAuthenticator::new();

    let user = User {
        username: hex::encode(hasher.finalize()),
        password: argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap(),
        twofa,
        secret: auth.create_secret(32), // création d'un secret de 32 bits même si 2fa désactivé
    };

    // si l'utilisateur existe déjà on quitte l'activité en cours
    if &conn
        .query(
            "SELECT secret FROM user_table WHERE username = $1",
            &[&user.username],
        )
        .unwrap()
        .len()
        > &0usize
    {
        if let Err(e) = writeln!(
            stdout,
            "Cet utilisateur existe déjà. Si vous avez oublié votre mot de passe utilisé l'option -p"
        ) {
            eprintln!("Writing error: {}", e.to_string());
        }
        return;
    }

    // insertion dans la base de donnée
    conn.execute(
        "INSERT INTO user_table (username, password, twofa, secret) VALUES ($1, $2, $3, $4)",
        &[&user.username, &user.password, &user.twofa, &user.secret],
    )
    .unwrap();
}
