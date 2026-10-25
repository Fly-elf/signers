use super::*;

#[test]
fn the_der_bytes_are_kept_as_given() {
    let certificate = Certificate::from_der(vec![0x30, 0x82, 0x01]);

    assert_eq!(certificate.der(), [0x30, 0x82, 0x01]);
    assert_eq!(certificate.into_der(), vec![0x30, 0x82, 0x01]);
}
