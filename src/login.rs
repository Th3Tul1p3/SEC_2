use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hex;
use postgres::{Connection, TlsMode};
use read_input::prelude::*;
use sha3::{Digest, Sha3_256};
use std::process;
use std::thread;
use validators;
use webbrowser;

struct User {
    password: String,
    twofa: bool,
    secret: String,
}

pub fn login(username: &str, password: &str) {

    // vérification de la validité des entrées
    let mut is_valid = true;
    is_valid &= validators::is_username_valid(username);
    is_valid &= validators::is_password_valid(password);
    if !is_valid {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        return;
    }

    // connexion à la DB
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

    //initialisations de sha3 pour vérifier le nom d'utilisateur
    let mut hasher = Sha3_256::new();
    hasher.update(username.to_owned().as_bytes());


    let rows = &conn
        .query(
            "SELECT password, twofa, secret FROM user_table WHERE username = $1",
            &[&hex::encode(hasher.finalize())],
        )
        .unwrap();

    // si l'utilisateur n'existe pas
    if rows.len() != 1usize {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        return;
    }

    let user = User {
        password: rows.get(0).get(0),
        twofa: rows.get(0).get(1),
        secret: rows.get(0).get(2),
    };

    // vérification du mot de passe
    if !argon2::verify_encoded(&user.password, password.as_bytes()).unwrap() {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        return;
    }

    // Si l'utilisateur a activer le 2fa on effectue la vérification
    if user.twofa {
        let auth = GoogleAuthenticator::new();

        let url = auth.qr_code_url(
            &user.secret,
            "qr_code",
            "name",
            200,
            200,
            ErrorCorrectionLevel::High,
        );

        // lancement du navigateur pour afficher le code QR
        let handle = thread::spawn(move || {
            webbrowser::open(&url).expect("failed to open URL");
        });
        handle.join().unwrap();

        // entrée utilisateur et vérification
        let input_token: String = input().repeat_msg("Please input your Token\n").get();
        if !auth.verify_code(&user.secret, &input_token, 0, 0) {
            return;
        }
    }
    println!("Vous êtes connecté.");
}
