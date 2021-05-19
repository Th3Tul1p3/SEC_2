use argon2::Config;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hex;
use postgres::Connection;
use rand::prelude::*;
use sha3::{Digest, Sha3_256};
use std::io;
use std::process::Command;

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
    browser: &str,
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

    if twofa {
show_qr_code(twofa, auth, &user, browser);
    }

    if let Err(e) = writeln!(stdout, "Utilisateur correctement enregistré.") {
        eprintln!("Writing error: {}", e.to_string());
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

#[cfg(test)]
mod test_register {
    use super::*;
    use postgres::{Connection, TlsMode};
    use std::process;

    #[test]
    pub fn registration() {
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
        assert_eq!(stdout, b"Utilisateur correctement enregistr\xc3\xA9.\n");

        stdout.clear();
        register(
            "toot.tutu@heig-vd.ch",
            "PiC$!@H%ucCuMt59$3UGzmxE",
            false,
            &mut stdout,
            &conn,
            "brave",
        );
        assert_eq!(stdout, b"Cet utilisateur existe d\xc3\xA9j\xc3\xA0. Si vous avez oubli\xc3\xA9 votre mot de passe utilis\xc3\xA9 l'option -p\n");
    }
}
