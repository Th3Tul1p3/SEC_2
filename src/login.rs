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
    browser: &str,
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

    // si l'utilisateur existe
    if rows.len() != 1usize {
        if let Err(e) = writeln!(
            stdout,
            "Le nom d'utilisateur et/ou le mot de passe ne sont pas valide."
        ) {
            eprintln!("Writing error: {}", e.to_string());
        }
        return;
    }

    let user = User {
        password: rows.get(0).get(0),
        twofa: rows.get(0).get(1),
        secret: rows.get(0).get(2),
    };

    // vérification du mot de passe
    if !argon2::verify_encoded(&user.password, password.as_bytes()).unwrap() {
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

        show_qr_code(twofa, auth, &user, browser);

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
        if validators::is_uuid_valid(&token) && token == msg && now.elapsed().as_secs() <= 60 {
            println!("Le token est correct.");

            if user.twofa && !verifiy_2fa(&user) {
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
                if let Err(e) = writeln!(
                    stdout,
                    "nouveau mot de passe incorrect ou temps dépassé, Processus annulé!"
                ) {
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

fn show_qr_code(twofa: bool, auth: GoogleAuthenticator, user: &User, browser: &str){
    if twofa {
        // création du code QR
        let url = auth.qr_code_url(
            &user.secret,
            "qr_code",
            "name",
            200,
            200,
            ErrorCorrectionLevel::High,
        );

        // affichage dans le navigateur ou le terminal
        if browser.is_empty() {
            println!("{:?}", &url);
        } else {
            Command::new(browser)
                .arg(&url)
                .spawn()
                .expect("Failed to start browser process");
        }
    }
}

fn verifiy_2fa(user: &User) -> bool {
    let auth = GoogleAuthenticator::new();

    // entrée utilisateur et vérification
    let input_token: String = input()
        .repeat_msg("Veuillez rentrer votre jeton de double authentification s.v.p.\n")
        .get();
    if !auth.verify_code(&user.secret, &input_token, 0, 0) {
        println!("Mauvais code.");
        return false;
    }
    true
}

#[cfg(test)]
mod test_login {
    use super::*;
    use crate::register::register;
    use postgres::{Connection, TlsMode};
    use std::process;

    #[test]
    pub fn simple_login() {
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

        conn.batch_execute("DROP TABLE user_table").unwrap();

        // création de la table user dans la DB
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS user_table (
            id              SERIAL PRIMARY KEY,
            username            VARCHAR NOT NULL,
            password         VARCHAR NOT NULL,
            twofa         boolean NOT NULL,
            secret         VARCHAR NOT NULL
        )",
        )
        .unwrap();

        let mut stdout = Vec::new();
        register(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            false,
            &mut stdout,
            &conn,
            "brave",
        );

        stdout.clear();

        login(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            false,
            false,
            &mut stdout,
            &conn,
            "brave",
        );
        assert_eq!(stdout, b"Vous \xc3\xAAtes connect\xc3\xA9.\n");
    }

    #[test]
    pub fn twofa_activation() {
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

        conn.batch_execute("DROP TABLE user_table").unwrap();

        // création de la table user dans la DB
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS user_table (
            id              SERIAL PRIMARY KEY,
            username            VARCHAR NOT NULL,
            password         VARCHAR NOT NULL,
            twofa         boolean NOT NULL,
            secret         VARCHAR NOT NULL
        )",
        )
        .unwrap();

        let mut stdout = Vec::new();
        register(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            false,
            &mut stdout,
            &conn,
            "brave",
        );

        stdout.clear();

        login(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            true,
            false,
            &mut stdout,
            &conn,
            "brave",
        );
        assert_eq!(stdout, b"Vous \xc3\xAAtes connect\xc3\xA9.\nVous avez demand\xc3\xA9 \xc3\xA0 activ\xc3\xA9 l'autentification double facteur\nAutentification double facteur activ\xc3\xA9e.\n");
    }

    #[test]
    pub fn user_dont_exist() {
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

        conn.batch_execute("DROP TABLE user_table").unwrap();

        // création de la table user dans la DB
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS user_table (
            id              SERIAL PRIMARY KEY,
            username            VARCHAR NOT NULL,
            password         VARCHAR NOT NULL,
            twofa         boolean NOT NULL,
            secret         VARCHAR NOT NULL
        )",
        )
        .unwrap();

        let mut stdout = Vec::new();
        stdout.clear();

        login(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            false,
            false,
            &mut stdout,
            &conn,
            "brave",
        );
        assert_eq!(
            stdout,
            b"Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.\n"
        );
    }
}
