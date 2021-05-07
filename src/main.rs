mod login;
mod register;
mod validator;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use read_input::prelude::*;
extern crate postgres;
use postgres::{Connection, TlsMode};

fn main() {
    let conn = Connection::connect(
        "postgresql://admin:S3c@localhost:5432/beautiful_db",
        TlsMode::None,
    )
    .unwrap();
    //let email_regex = Regex::new(r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$").unwrap();
    //let password_regex = Regex::new(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{4,8}$").unwrap();

    let auth = GoogleAuthenticator::new();
    //let code = auth.create_secret(20);
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";

    println!(
        "{}",
        auth.qr_code_url(
            &secret,
            "qr_code",
            "name",
            400,
            400,
            ErrorCorrectionLevel::High
        )
    );

    loop {
        let input_token: String = input().repeat_msg("Please input your Token\n").get();

        if auth.verify_code(&secret, &input_token, 0, 0) {
            println!("match!");
            break;
        }
    }
}
