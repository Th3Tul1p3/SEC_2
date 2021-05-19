mod login;
mod register;
extern crate postgres;
use postgres::{Connection, TlsMode};
use std::io;
use std::process;
use structopt::StructOpt;
use validators;

#[derive(StructOpt, Debug)]
#[structopt(name = "laboratoire_2")]
struct Cli {
    /// If you want to login
    #[structopt(short, long)]
    login: bool,

    /// If you want to register
    #[structopt(short, long)]
    register: bool,

    /// If you want to reset password
    #[structopt(short, long)]
    password_reset: bool,

    /// If you want to disable/enable 2fa
    #[structopt(short, long)]
    twofa: bool,

    /// enter username
    #[structopt(long = "username", default_value = "")]
    username: String,

    /// enter password
    #[structopt(long = "password", default_value = "")]
    password: String,

    /// to open open 2fa
    /// tested with brave and firefox
    #[structopt(long = "browser", default_value = "")]
    browser: String,
}

fn main() {
    let opt = Cli::from_args();

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

    /*conn.batch_execute("DROP TABLE user_table").unwrap();*/

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

    // vérification de la validité des arguments
    let mut is_valid = true;
    is_valid &= validators::is_username_valid(&opt.username);
    is_valid &= validators::is_password_valid(&opt.password);
    if !is_valid {
        println!("Le nom d'utilisateur et/ou le mot de passe ne sont pas valide.");
        process::exit(0x0100);
    }

    if opt.login {
        login::login(
            &opt.username,
            &opt.password,
            opt.twofa,
            opt.password_reset,
            &mut io::stdout(),
            &conn,
            &opt.browser,
        );
    } else if opt.register {
        register::register(
            &opt.username,
            &opt.password,
            opt.twofa,
            &mut io::stdout(),
            &conn,
            &opt.browser,
        );
    }
}
