mod login;
mod register;
extern crate postgres;
use postgres::{Connection, TlsMode};
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

    /// If you want to disable/enable 2fa par défaut activer
    #[structopt(short, long)]
    twofa: bool,

    /// enter username
    #[structopt(long = "username", default_value = "")]
    username: String,

    /// enter password
    #[structopt(long = "password", default_value = "")]
    password: String,
}

fn main() {
    let opt = Cli::from_args();
    println!("{:#?}", opt);

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

    if opt.login {
        login::login(&opt.username, &opt.password);
    } else if opt.register {
        register::register(&opt.username, &opt.password, opt.twofa);
    } else {
    }
}
