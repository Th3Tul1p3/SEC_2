mod login;
mod register;
extern crate postgres;
use argon2::Config;
use hex;
use postgres::{Connection, TlsMode};
use sha3::{Digest, Sha3_256};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
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
}

struct User {
    username: String,
    password: String,
    twofa: bool,
}

fn main() {
    let password = b"P@ssw0rd";
    let salt = b"randomsalt";
    let config = Config::default();
    let hash = argon2::hash_encoded(password, salt, &config).unwrap();

    let opt = Cli::from_args();
    println!("{:#?}", opt);

    let mut hasher = Sha3_256::new();
    hasher.update("jerome.arn@heig-vd.ch".to_owned().as_bytes());

    // read hash digest
    let result = hex::encode(hasher.finalize());
    let user = User {
        username: result,
        password: hash,
        twofa: true,
    };

    let conn: Connection = Connection::connect(
        "postgresql://admin:S3c@localhost:5432/beautiful_db",
        TlsMode::None,
    )
    .unwrap();

    conn.batch_execute(
        "
    CREATE TABLE IF NOT EXISTS user_table (
        id              SERIAL PRIMARY KEY,
        username            VARCHAR NOT NULL,
        password         VARCHAR NOT NULL,
        twofa         boolean NOT NULL
        )
",
    )
    .unwrap();

    /*conn.execute(
        "INSERT INTO user_table (username, password, twofa) VALUES ($1, $2, $3)",
        &[&user.username, &user.password, &user.twofa],
    )
    .unwrap();*/

    if opt.login {
        login::login(&opt.username, &opt.password);
    } else if opt.register {
    } else {
    }
}
