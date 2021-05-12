use lazy_static::lazy_static;
extern crate regex;
use regex::Regex;
use regex::RegexSet;

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
    let uuid_regex = Regex::new(r"^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$").unwrap();
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
        ::trace // Traces testing for easier debugging
    )]
    pub fn user_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_username_valid(&input));
    }

    #[rstest(
        input,
        expected,
        case("57VYJL34", false),
        case("p^6SF%FH", true),
        ::trace // Traces testing for easier debugging
    )]
    pub fn password_not_valid(input: &str, expected: bool) {
        assert_eq!(expected, is_password_valid(&input));
    }
}
