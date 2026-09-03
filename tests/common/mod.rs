// Copyright (c) 2026 Edison Lepiten / AIEONYX

pub fn record_new(
    id: &str,
    tier: edisondb::DataTier,
    owner_id: &str,
    payload: Vec<u8>,
    salt: [u8; 32],
) -> Result<edisondb::Record, edisondb::EdisonError> {
    let key = [0x5au8; 32];

    edisondb::Record::new(
        id,
        tier,
        owner_id,
        &payload,
        &key,
        salt,
    )
}
