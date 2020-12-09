//! Some useful utilities for the library

///
/// converts oid-string like "1.3.6" into vector Vec<u32>[1, 3, 6, 0]
///
/// # Examples
/// ```
/// use snmp::utils::oid_str_to_vec32;
///
/// assert_eq!(oid_str_to_vec32("1.3.6"), Ok(vec![1, 3, 6, 0]));
///
/// // skip a leading dot
/// assert_eq!(oid_str_to_vec32(".1.3.6"), Ok(vec![1, 3, 6, 0]));
///
/// // do not add extra zero at end
/// assert_eq!(oid_str_to_vec32("1.3.6.0"), Ok(vec![1, 3, 6, 0]));
///
/// // wrong oid
/// assert!(oid_str_to_vec32("1.3.6.").is_err());
/// ```
pub fn oid_str_to_vec32(oid: &str) -> Result<Vec<u32>, String> {
    // skip a leading dot
    let oid2 = if oid.starts_with('.') { &oid[1..] } else { oid };

    let result: Result<Vec<u32>, _> = oid2
        .split('.')
        .map(|s| -> Result<u32, String> { s.parse::<u32>().map_err(|e| e.to_string()) })
        .collect();

    if let Ok(mut vec1) = result {
        // add trailing zero?
        if vec1.last() != Some(&0) {
            vec1.push(0);
        }
        Ok(vec1)
    } else {
        result
    }
}
