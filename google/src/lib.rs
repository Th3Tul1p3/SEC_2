use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use std::process::Command;
use read_input::prelude::*;

pub fn show_qr_code(twofa: bool, auth: GoogleAuthenticator, user_secret: &str, browser: &str){
    if twofa {
        // création du code QR
        let url = auth.qr_code_url(
            user_secret,
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

pub fn verifiy_2fa(user_secret: &str) -> bool {
    let auth = GoogleAuthenticator::new();

    // entrée utilisateur et vérification
    let input_token: String = input()
        .repeat_msg("Veuillez rentrer votre jeton de double authentification s.v.p.\n")
        .get();
    if !auth.verify_code(user_secret, &input_token, 0, 0) {
        println!("Mauvais code.");
        return false;
    }
    true
}
