use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hex;
use image::Luma;
use postgres::{Connection, TlsMode};
use qrcode::QrCode;
use read_input::prelude::*;
use sha3::{Digest, Sha3_256};
use std::thread;
use validators;
use webbrowser;

struct User {
    username: String,
    password: String,
    twofa: bool,
}

pub fn login(username: &str, password: &str) -> bool {
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

    let rows = &conn
        .query(
            "SELECT password, twofa FROM user_table WHERE username = $1",
            &[&hex::encode(hasher.finalize())],
        )
        .unwrap();

    let user = User {
        username: username.to_string(),
        password: rows.get(0).get(0),
        twofa: rows.get(0).get(1),
    };

    let matches = argon2::verify_encoded(&user.password, password.as_bytes()).unwrap();
    println!("{:?}", matches);

    if user.twofa {
        let auth = GoogleAuthenticator::new();
        //let code = auth.create_secret(20);
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        // Encode some data into bits.

        let url = auth.qr_code_url(
            secret,
            "qr_code",
            "name",
            200,
            200,
            ErrorCorrectionLevel::High,
        );

        let handle = thread::spawn(move || {
            webbrowser::open(&url).expect("failed to open URL");
        });

        handle.join().unwrap();

        let input_token: String = input().repeat_msg("Please input your Token\n").get();

        if auth.verify_code(&secret, &input_token, 0, 0) {
            println!("match!");
        }
    }
    is_valid
}
