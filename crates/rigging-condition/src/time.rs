//! Timestamps and durations at microsecond precision, with their CEL text forms.

use std::fmt;

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
/// CEL's duration range: plus or minus 10,000 years of 365.25 days.
const MAX_DURATION_SECONDS: i64 = 315_576_000_000;

/// An instant in UTC, as whole microseconds since the Unix epoch, within CEL's
/// range `0001-01-01T00:00:00Z` to `9999-12-31T23:59:59.999999Z`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// A signed span, as whole microseconds, within CEL's range of ±315,576,000,000 seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(i64);

/// Why a timestamp or duration string was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeError(pub(crate) &'static str);

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for TimeError {}

fn min_timestamp() -> i64 {
    days_from_civil(1, 1, 1) * SECONDS_PER_DAY * MICROS_PER_SECOND
}

fn max_timestamp() -> i64 {
    (days_from_civil(9999, 12, 31) + 1) * SECONDS_PER_DAY * MICROS_PER_SECOND - 1
}

impl Timestamp {
    /// The instant `micros` microseconds after the epoch, if it is in range.
    pub fn from_unix_micros(micros: i64) -> Option<Self> {
        (min_timestamp()..=max_timestamp()).contains(&micros).then_some(Timestamp(micros))
    }

    pub fn unix_micros(self) -> i64 {
        self.0
    }

    /// Parses RFC 3339 text: `YYYY-MM-DDTHH:MM:SS[.f]` then `Z` or `±HH:MM`.
    /// At most six fractional digits, since storage is microseconds.
    pub fn parse_rfc3339(text: &str) -> Result<Self, TimeError> {
        let b = text.as_bytes();
        let digits = |range: std::ops::Range<usize>| -> Result<i64, TimeError> {
            let part = b.get(range).ok_or(TimeError("timestamp is too short"))?;
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return Err(TimeError("timestamp has a non-digit where a digit is required"));
            }
            Ok(part.iter().fold(0, |n, d| n * 10 + i64::from(d - b'0')))
        };
        let expect = |at: usize, options: &[u8]| -> Result<(), TimeError> {
            match b.get(at) {
                Some(c) if options.contains(c) => Ok(()),
                _ => Err(TimeError("timestamp is not RFC 3339")),
            }
        };
        let year = digits(0..4)?;
        expect(4, b"-")?;
        let month = digits(5..7)?;
        expect(7, b"-")?;
        let day = digits(8..10)?;
        expect(10, b"Tt")?;
        let hour = digits(11..13)?;
        expect(13, b":")?;
        let minute = digits(14..16)?;
        expect(16, b":")?;
        let second = digits(17..19)?;
        let mut at = 19;
        let mut micros = 0;
        if b.get(at) == Some(&b'.') {
            let start = at + 1;
            let len = b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
            if len == 0 {
                return Err(TimeError("timestamp has an empty fraction"));
            }
            if len > 6 {
                return Err(TimeError("timestamp has more than six fractional digits"));
            }
            micros = digits(start..start + len)? * 10_i64.pow(6 - len as u32);
            at = start + len;
        }
        let offset_seconds = match b.get(at) {
            Some(b'Z' | b'z') if at + 1 == b.len() => 0,
            Some(sign @ (b'+' | b'-')) if at + 6 == b.len() => {
                expect(at + 3, b":")?;
                let (h, m) = (digits(at + 1..at + 3)?, digits(at + 4..at + 6)?);
                if h > 23 || m > 59 {
                    return Err(TimeError("timestamp offset is out of range"));
                }
                let offset = h * 3600 + m * 60;
                if *sign == b'-' { -offset } else { offset }
            }
            _ => return Err(TimeError("timestamp needs a Z or ±HH:MM offset")),
        };
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return Err(TimeError("timestamp date is out of range"));
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err(TimeError("timestamp time is out of range"));
        }
        let seconds = days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second - offset_seconds;
        Timestamp::from_unix_micros(seconds * MICROS_PER_SECOND + micros).ok_or(TimeError("timestamp is outside 0001-01-01 to 9999-12-31"))
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`, the fraction trimmed of trailing zeros and
/// omitted when zero.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0.div_euclid(MICROS_PER_SECOND);
        let micros = self.0.rem_euclid(MICROS_PER_SECOND);
        let (days, second_of_day) = (seconds.div_euclid(SECONDS_PER_DAY), seconds.rem_euclid(SECONDS_PER_DAY));
        let (year, month, day) = civil_from_days(days);
        write!(f, "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}", second_of_day / 3600, second_of_day / 60 % 60, second_of_day % 60)?;
        write_fraction(f, micros)?;
        f.write_str("Z")
    }
}

impl Duration {
    /// The span of `micros` microseconds, if it is in range.
    pub fn from_micros(micros: i64) -> Option<Self> {
        let max = MAX_DURATION_SECONDS * MICROS_PER_SECOND;
        (-max..=max).contains(&micros).then_some(Duration(micros))
    }

    pub fn micros(self) -> i64 {
        self.0
    }

    /// Parses CEL's duration syntax: an optional sign, then one or more
    /// decimal numbers each followed by a unit `h`, `m`, `s`, `ms` or `us`
    /// (`1h30m`, `-1.5s`, `300ms`). `ns` and anything below a microsecond are
    /// refused; CEL has no days.
    pub fn parse(text: &str) -> Result<Self, TimeError> {
        let (negative, mut rest) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        if rest.is_empty() {
            return Err(TimeError("duration is empty"));
        }
        let mut total: i128 = 0;
        while !rest.is_empty() {
            let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
            let (int_part, after) = rest.split_at(int_len);
            let (frac_part, after) = match after.strip_prefix('.') {
                Some(after) => after.split_at(after.bytes().take_while(u8::is_ascii_digit).count()),
                None => ("", after),
            };
            if int_part.is_empty() && frac_part.is_empty() {
                return Err(TimeError("duration needs a number before each unit"));
            }
            let unit_len = after.bytes().take_while(u8::is_ascii_alphabetic).count();
            let (unit, after) = after.split_at(unit_len);
            let unit_micros: i128 = match unit {
                "h" => 3_600_000_000,
                "m" => 60_000_000,
                "s" => 1_000_000,
                "ms" => 1_000,
                "us" => 1,
                "ns" => return Err(TimeError("duration unit ns is below the microsecond precision")),
                "" => return Err(TimeError("duration needs a unit")),
                _ => return Err(TimeError("duration unit must be h, m, s, ms or us")),
            };
            // Too many digits can only overflow the range; refuse before parsing.
            if int_part.len() > 20 || frac_part.len() > 20 {
                return Err(TimeError("duration is out of range"));
            }
            let whole: i128 = if int_part.is_empty() { 0 } else { int_part.parse().map_err(|_| TimeError("duration is out of range"))? };
            let scale = 10_i128.pow(frac_part.len() as u32);
            let frac: i128 = if frac_part.is_empty() { 0 } else { frac_part.parse().map_err(|_| TimeError("duration is out of range"))? };
            if (frac * unit_micros) % scale != 0 {
                return Err(TimeError("duration is finer than a microsecond"));
            }
            total += whole * unit_micros + frac * unit_micros / scale;
            if total > i128::from(MAX_DURATION_SECONDS * MICROS_PER_SECOND) {
                return Err(TimeError("duration is out of range"));
            }
            rest = after;
        }
        let micros = i64::try_from(if negative { -total } else { total }).map_err(|_| TimeError("duration is out of range"))?;
        Duration::from_micros(micros).ok_or(TimeError("duration is out of range"))
    }
}

/// `<seconds>[.ffffff]s`, the protobuf JSON form, trimmed like a timestamp.
impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            f.write_str("-")?;
        }
        let magnitude = self.0.unsigned_abs();
        write!(f, "{}", magnitude / 1_000_000)?;
        write_fraction(f, (magnitude % 1_000_000) as i64)?;
        f.write_str("s")
    }
}

fn write_fraction(f: &mut fmt::Formatter<'_>, micros: i64) -> fmt::Result {
    if micros == 0 {
        return Ok(());
    }
    let digits = format!("{micros:06}");
    write!(f, ".{}", digits.trim_end_matches('0'))
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}
