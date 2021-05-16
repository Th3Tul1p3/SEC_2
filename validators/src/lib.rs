use lazy_static::lazy_static;
extern crate regex;
use regex::Regex;
use regex::RegexSet;
use zxcvbn::zxcvbn;

pub fn is_username_valid(username: &str) -> bool {
    let mut is_valid: bool = true;

    lazy_static! {
        static ref USERNAME_REGEX: Regex =
            Regex::new(r"^[\w_+&*-]+(?:\.[\w_+&*-]+)*@(?:[\w-]+\.)+[a-zA-Z]{2,7}$").unwrap();
    }

    is_valid &= USERNAME_REGEX.is_match(username);
    is_valid
}

pub fn is_password_valid(password: &str) -> bool {
    let mut is_valid: bool = true;

    let estimate = zxcvbn(&password, &[]).unwrap();
    is_valid &= estimate.score() >= 3;

    if estimate.score() <= 2 {
        println!("Il semblerait que votre mot de passe n'est pas assez fort!");
        println!(
            "Il pourrait être deviné en {} tentatives.",
            estimate.guesses()
        );
        println!("Voici quelques suggestions pour vous aider :");
        for i in estimate
            .feedback()
            .as_ref()
            .unwrap()
            .suggestions()
            .into_iter()
        {
            println!("{}", i);
        }
    }

    lazy_static! {
        static ref PASSWORD_REGEX: RegexSet = RegexSet::new(&[
            r"[a-z]+",
            r"[A-Z]+",
            r"[0-9]+",
            r"[!@#$%^&*]+",
            r"^[\w!@#$%^&*]{8,64}$"
        ])
        .unwrap();
    }

    let matches: Vec<_> = PASSWORD_REGEX.matches(password).into_iter().collect();
    is_valid &= PASSWORD_REGEX.len() == matches.len();
    is_valid
}

pub fn is_uuid_valid(uuid: &str) -> bool {
    let uuid_regex = Regex::new(
        r"^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$",
    )
    .unwrap();
    return uuid_regex.is_match(&uuid);
}

#[cfg(test)]
mod test_globbing {
    use super::*;
    use rstest::rstest;
    #[rstest(
        input,
        expected,
        case("jerome.arn@heig-vd.ch", true),
        case("jerome.arn.1443@gmail.com", true),
        ::trace // Traces testing for easier debugging
    )]
    pub fn user_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_username_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("jerome.arn", false),
        case("jerome.arn@heig", false),
        case("jerome.arnheig.ch", false),
        ::trace // Traces testing for easier debugging
    )]
    pub fn user_not_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_username_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("U$&H64zvBrT6J*4D!ouaa^QA", true),
        case("R7sJRC@7!62U!FqQqXEWUvsq&W5F9@FvPr#QaXo2Xfx3bkVBaXiMshVqtrs4gSEG", true),
        case("tQ2#qroQ112TG##", true),
        ::trace // Traces testing for easier debugging
    )]
    pub fn password_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_password_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("57VYJL34", false),
        case("st$RGeqQumHq5qxC5oBhN%2$As8Et7vG$8RwwtBt*GfZ5Vtcnr4eQNo5RMxzHZnz6", false),
        case("#6KEY$r", false),
        case("p2hZA7gc8BvZn3cJG6dD42bB", false),
        case("hpBTCEYiwgwhz@K^gCiaxtdB", false),
        case("V!H%4WAM##N&KREX46STMUJB", false),
        case("rjoannk7v7%h@dp6@c!#j7fo", false),
        case("P@ssw0rd", false),
        case("tQ2#qroQ", false),
        ::trace // Traces testing for easier debugging
    )]
    pub fn password_not_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_password_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("09f5b52a-cd67-40b8-aead-b26fd04ed611", true),
        case("df3e6fc4-3ec5-42d3-8c38-54e097ea41a4", true),
        case("8a04e0ec-0749-44a8-bbc5-1c9fcbd97b33", true),
        case("bab5f027-d542-45be-9c2b-aa470eaf169d", true),
        ::trace // Traces testing for easier debugging
    )]
    pub fn uuid_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_uuid_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("123456", false),
        case("09f5b52a-cd67-40b8", false),
        ::trace // Traces testing for easier debugging
    )]
    pub fn uuid_not_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_uuid_valid(&input));
    }
}
