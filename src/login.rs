use argon2::Config;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hex;
use mail_sender;
use postgres::{Connection, TlsMode};
use rand::prelude::*;
use read_input::prelude::*;
use sha3::{Digest, Sha3_256};
use std::process;
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;
use validators;

struct User {
    password: String,
    twofa: bool,
    secret: String,
}

pub fn login(username: &str, password: &str, twofa: bool, password_reset: bool) {
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
    let result = &hex::encode(hasher.finalize());

    let rows = &conn
        .query(
            "SELECT password, twofa, secret FROM user_table WHERE username = $1",
            &[&result],
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
    if user.twofa && !verifiy_2fa(&user) {
        return;
    }

    println!("Vous êtes connecté.");

    if twofa && user.twofa {
        println!("Vous avez demandé à désactivé l'autentification double facteur");
        if !verifiy_2fa(&user) {
            return;
        }

        conn.execute(
            "UPDATE user_table SET twofa = $1 WHERE username = $2",
            &[&false, &result],
        )
        .unwrap();
        println!("Autentification double facteur désactivée.");
    } else if twofa && !user.twofa {
        // configuration google authenticator
        let auth = GoogleAuthenticator::new();

        println!("Vous avez demandé à activé l'autentification double facteur");
        conn.execute(
            "UPDATE user_table SET twofa = $1, secret = $2 WHERE username = $3",
            &[&true, &auth.create_secret(32), &result],
        )
        .unwrap();
        println!("Autentification double facteur activée.");
    }

    if password_reset {
        println!("Vous avez demandé à changer votre mot de passe...");
        let msg = Uuid::new_v4().to_hyphenated().to_string();
        let now = Instant::now();

        if !mail_sender::send_mail(&username, &msg) {
            return;
        }

        let token: String = input()
            .msg("Entrez votre token: ")
            .err("Veuillez entrer une chaîne de caractère")
            .get();
        if validators::is_uuid_valid(&token) && token == msg && now.elapsed().as_secs() <= 15 * 60 {
            println!("Le token est correct.");

            if !verifiy_2fa(&user) {
                return;
            }

            let new_password: String = input()
                .msg("Entrez votre nouveau mot de passe: ")
                .err("Veuillez entrer une chaîne de caractère")
                .get();
            if validators::is_password_valid(&new_password) {
                // génération du sel pour argon2
                let mut salt = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut salt);

                // configuration argon2
                let config = Config::default();

                conn.execute(
                    "UPDATE user_table SET password = $1 WHERE username = $2",
                    &[
                        &argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap(),
                        &username,
                    ],
                )
                .unwrap();
            } else {
                println!("nouveau mot de passe incorrect, Processus annulé!");
            }
        } else {
            println!("Mauvais Token, Processus annulé!");
        }
    }
}

fn verifiy_2fa(user: &User) -> bool {
    let auth = GoogleAuthenticator::new();

    let url = auth.qr_code_url(
        &user.secret,
        "qr_code",
        "name",
        200,
        200,
        ErrorCorrectionLevel::High,
    );

    Command::new("brave")
        .arg(url)
        .spawn()
        .expect("Failed to start sed process");

    //println!("{:?}", url);

    // entrée utilisateur et vérification
    let input_token: String = input().repeat_msg("Please input your Token\n").get();
    if !auth.verify_code(&user.secret, &input_token, 0, 0) {
        println!("Mauvais code.");
        return false;
    }
    true
}
