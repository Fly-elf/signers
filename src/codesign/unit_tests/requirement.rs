use super::*;
use crate::errors::ProcessError;

fn requirement(line: &str) -> Requirement {
    Requirement::parse(line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
}

#[test]
fn a_requirement_line_splits_into_kind_and_expression() {
    let found = requirement(r#"designated => identifier "com.apple.ls" and anchor apple"#);

    assert_eq!(
        found,
        Requirement {
            kind: RequirementKind::Designated,
            expression: r#"identifier "com.apple.ls" and anchor apple"#.into(),
            implicit: false,
        }
    );
}

#[test]
fn every_known_kind_is_recognised() {
    let cases = [
        ("designated", RequirementKind::Designated),
        ("host", RequirementKind::Host),
        ("guest", RequirementKind::Guest),
        ("library", RequirementKind::Library),
        ("plugin", RequirementKind::Plugin),
    ];

    for (word, kind) in cases {
        let found = requirement(&format!("{word} => anchor apple"));
        assert_eq!(found.kind, kind, "{word}");
        assert_eq!(found.expression, "anchor apple");
        assert!(!found.implicit, "{word}");
    }
}

#[test]
fn an_unknown_kind_keeps_its_word() {
    assert_eq!(
        requirement("something => anchor apple").kind,
        RequirementKind::Other("something".into())
    );
    assert_eq!(
        requirement("Designated => anchor apple").kind,
        RequirementKind::Other("Designated".into()),
        "kinds are lower case"
    );
}

#[test]
fn a_hash_prefix_marks_the_requirement_as_implicit() {
    let found = requirement(r#"# designated => cdhash H"da0b" or cdhash H"c0ffee""#);

    assert!(found.implicit);
    assert_eq!(found.kind, RequirementKind::Designated);
    assert_eq!(found.expression, r#"cdhash H"da0b" or cdhash H"c0ffee""#);
    assert!(!requirement("designated => anchor apple").implicit);
}

#[test]
fn an_expression_may_contain_the_separator() {
    let found = requirement(r#"designated => identifier "a => b" and anchor apple"#);

    assert_eq!(found.kind, RequirementKind::Designated);
    assert_eq!(found.expression, r#"identifier "a => b" and anchor apple"#);
}

#[test]
fn a_line_without_the_separator_is_rejected() {
    for line in [
        "",
        "designated",
        "designated=>anchor apple",
        "designated =>anchor apple",
        "designated  anchor apple",
        "# designated",
    ] {
        let result = Requirement::parse(line);
        assert!(
            matches!(
                result,
                Err(crate::Error::Process(ProcessError::UnexpectedOutput {
                    program: "codesign",
                    ..
                }))
            ),
            "{line:?}: {result:?}"
        );
    }
}
