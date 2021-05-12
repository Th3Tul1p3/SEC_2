use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

const SMTP_USER: &str = "jerome.arn.1443@gmail.com";
const SMTP_PASS: &str = "asxt clhc wphq wvei";
const SMTP_SERV: &str = "smtp.gmail.com";
const MAIL_FROM: &str = "admin <jerome.arn.1443@gmail.com>";

pub fn send_mail(dst: &str, message: &str) -> bool{
    let email = Message::builder()
        .from(MAIL_FROM.parse().unwrap())
        .reply_to(MAIL_FROM.parse().unwrap())
        .to(dst.parse().unwrap())
        .subject("Changement de mot de passe")
        .body(format!("Votre token pour la validation du changement de mot de passe : {}", message))
        .unwrap();
    let creds = Credentials::new(SMTP_USER.to_string(), SMTP_PASS.to_string());

    let mailer = SmtpTransport::relay(SMTP_SERV)
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => println!("Un mail vous a été envoyé avec un token."),
        Err(e) => {println!("Le mail n'a pas pu être envoyé : {:?}", e); return false;},
    }
    true
}
