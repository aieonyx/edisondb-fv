// Copyright (c) 2026 Edison Lepiten / AIEONYX

#[test]
fn public_record_cannot_be_deserialized() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/p1b_record_deserialize.rs");
}
