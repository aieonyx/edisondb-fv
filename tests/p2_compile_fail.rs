// Copyright (c) 2026 Edison Lepiten / AIEONYX

#[test]
fn aad_bound_record_fields_are_not_publicly_mutable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/p2_record_id_mutation.rs");
    cases.compile_fail("tests/ui/p2_record_tier_mutation.rs");
}
