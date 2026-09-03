// Copyright (c) 2026 Edison Lepiten / AIEONYX

use edisondb::{DataTier, Record};

fn mutate(record: &mut Record) {
    record.tier = DataTier::Noise;
}

fn main() {}
