use argon2::Config;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hex;
use mail_sender;
use postgres::Connection;
use rand::prelude::*;
use read_input::prelude::*;
use sha3::{Digest, Sha3_256};
use std::io;
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;

struct User {
    password: String,
    twofa: bool,
    secret: String,
}

pub fn login(
    username: &str,
    password: &str,
    twofa: bool,
    password_reset: bool,
    stdout: &mut dyn io::Write,
    conn: &Connection,
) {
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

    let user = User {
        password: rows.get(0).get(0),
        twofa: rows.get(0).get(1),
        secret: rows.get(0).get(2),
    };

    // vérification du mot de passe et si l'utilisateur existe
    if !argon2::verify_encoded(&user.password, password.as_bytes()).unwrap() || rows.len() != 1usize
    {
        if let Err(e) = writeln!(
            stdout,
            "Le nom d'utilisateur et/ou le mot de passe ne sont pas valide."
        ) {
            eprintln!("Writing error: {}", e.to_string());
        }
        return;
    }

    // Si l'utilisateur a activer le 2fa on effectue la vérification
    if user.twofa && !verifiy_2fa(&user) {
        return;
    }

    if let Err(e) = writeln!(stdout, "Vous êtes connecté.") {
        eprintln!("Writing error: {}", e.to_string());
    }

    if twofa && user.twofa {
        if let Err(e) = writeln!(
            stdout,
            "Vous avez demandé à désactivé l'autentification double facteur"
        ) {
            eprintln!("Writing error: {}", e.to_string());
        }

        if !verifiy_2fa(&user) {
            return;
        }

        conn.execute(
            "UPDATE user_table SET twofa = $1 WHERE username = $2",
            &[&false, &result],
        )
        .unwrap();

        if let Err(e) = writeln!(stdout, "Autentification double facteur désactivée.") {
            eprintln!("Writing error: {}", e.to_string());
        }
    } else if twofa && !user.twofa {
        // configuration google authenticator
        let auth = GoogleAuthenticator::new();

        if let Err(e) = writeln!(
            stdout,
            "Vous avez demandé à activé l'autentification double facteur"
        ) {
            eprintln!("Writing error: {}", e.to_string());
        }

        conn.execute(
            "UPDATE user_table SET twofa = $1, secret = $2 WHERE username = $3",
            &[&true, &auth.create_secret(32), &result],
        )
        .unwrap();

        if let Err(e) = writeln!(stdout, "Autentification double facteur activée.") {
            eprintln!("Writing error: {}", e.to_string());
        }
    }

    if password_reset {
        if let Err(e) = writeln!(stdout, "Vous avez demandé à changer votre mot de passe...") {
            eprintln!("Writing error: {}", e.to_string());
        }

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
                if let Err(e) =
                    writeln!(stdout, "nouveau mot de passe incorrect, Processus annulé!")
                {
                    eprintln!("Writing error: {}", e.to_string());
                }
            }
        } else {
            if let Err(e) = writeln!(stdout, "Mauvais Token, Processus annulé!") {
                eprintln!("Writing error: {}", e.to_string());
            }
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
