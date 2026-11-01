//! Timestamp text (§4.3) against chrono, an independent RFC 3339 implementation.

use chrono::{DateTime, Datelike, FixedOffset, SecondsFormat};
use hegel::{TestCase, generators as gs};
use rigging_condition::Timestamp;

// CEL's range, 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999Z.
const MIN_MICROS: i64 = -62_135_596_800_000_000;
const MAX_MICROS: i64 = 253_402_300_799_999_999;

// Behaviour: over every instant in CEL's range, at microsecond precision
// (its ends and the epoch drawn often),
// the print is chrono's UTC date and time with the fraction trimmed of
// trailing zeros, and chrono parses it back to the instant; and chrono's
// RFC 3339 text for the instant at any offset parses to the instant, when
// its local date has a four-digit year (RFC 3339 has no other).
#[hegel::test(test_cases = 1000)]
fn timestamp_text_agrees_with_chrono(tc: TestCase) {
    let micros = if tc.draw(gs::weighted_booleans(0.1)) {
        tc.draw(gs::sampled_from(vec![MIN_MICROS, MIN_MICROS + 1, -1, 0, 1, MAX_MICROS - 1, MAX_MICROS]))
    } else {
        tc.draw(gs::integers::<i64>().min_value(MIN_MICROS).max_value(MAX_MICROS))
    };
    let ours = Timestamp::from_unix_micros(micros).unwrap();
    let theirs = DateTime::from_timestamp_micros(micros).unwrap();

    let printed = ours.to_string();
    let fraction = theirs.format("%.6f").to_string();
    let fraction = fraction.trim_end_matches('0').trim_end_matches('.');
    assert_eq!(printed, format!("{}{fraction}Z", theirs.format("%Y-%m-%dT%H:%M:%S")));
    assert_eq!(DateTime::parse_from_rfc3339(&printed).map(|t| t.timestamp_micros()), Ok(micros), "{printed}");

    let offset = FixedOffset::east_opt(tc.draw(gs::integers::<i32>().min_value(-(23 * 60 + 59)).max_value(23 * 60 + 59)) * 60).unwrap();
    let local = theirs.with_timezone(&offset);
    let format = if tc.draw(gs::booleans()) { SecondsFormat::Micros } else { SecondsFormat::AutoSi };
    let text = local.to_rfc3339_opts(format, tc.draw(gs::booleans()));
    let parsed = Timestamp::parse_rfc3339(&text);
    if (0..=9999).contains(&local.year()) {
        assert_eq!(parsed, Ok(ours), "{text}");
    } else {
        assert!(parsed.is_err(), "{text}");
    }
}

// Years where the Gregorian leap rule turns, and both ends of the range.
const YEARS: &[i64] = &[1, 4, 100, 400, 1600, 1700, 1900, 1970, 2000, 2024, 2100, 2400, 9600, 9996, 9999];

// Behaviour: RFC 3339 text built field by field (any day up to 31 in any
// month, often February 29 and month ends, in leap and non-leap years, any
// offset, zero to six fractional digits) parses exactly when chrono parses
// it to an instant in CEL's range, and then to the same instant.
#[hegel::test(test_cases = 1000)]
fn timestamp_parse_agrees_with_chrono(tc: TestCase) {
    let year = if tc.draw(gs::booleans()) {
        tc.draw(gs::sampled_from(YEARS.to_vec()))
    } else {
        tc.draw(gs::integers::<i64>().min_value(1).max_value(9999))
    };
    // February and the last days of a month, often.
    let month = if tc.draw(gs::booleans()) { 2 } else { tc.draw(gs::integers::<u32>().min_value(1).max_value(12)) };
    let day = match tc.draw(gs::integers::<u8>().max_value(2)) {
        0 => 29,
        1 => tc.draw(gs::integers::<u32>().min_value(28).max_value(31)),
        _ => tc.draw(gs::integers::<u32>().min_value(1).max_value(31)),
    };
    let (hour, minute, second) = (
        tc.draw(gs::integers::<u32>().max_value(23)),
        tc.draw(gs::integers::<u32>().max_value(59)),
        tc.draw(gs::integers::<u32>().max_value(59)),
    );
    let digits = tc.draw(gs::integers::<usize>().max_value(6));
    let fraction: String = (0..digits).map(|_| char::from(b'0' + tc.draw(gs::integers::<u8>().max_value(9)))).collect();
    let fraction = if digits == 0 { String::new() } else { format!(".{fraction}") };
    let offset = match tc.draw(gs::integers::<u8>().max_value(2)) {
        0 => "Z".to_owned(),
        1 => "z".to_owned(),
        _ => {
            let minutes = tc.draw(gs::integers::<i32>().min_value(-(23 * 60 + 59)).max_value(23 * 60 + 59));
            format!("{}{:02}:{:02}", if minutes < 0 { '-' } else { '+' }, minutes.abs() / 60, minutes.abs() % 60)
        }
    };
    let separator = if tc.draw(gs::booleans()) { 'T' } else { 't' };
    let text = format!("{year:04}-{month:02}-{day:02}{separator}{hour:02}:{minute:02}:{second:02}{fraction}{offset}");

    let theirs = DateTime::parse_from_rfc3339(&text).ok().map(|t| t.timestamp_micros()).filter(|m| (MIN_MICROS..=MAX_MICROS).contains(m));
    assert_eq!(Timestamp::parse_rfc3339(&text).ok().map(Timestamp::unix_micros), theirs, "{text}");
}
