use crate::cvt::cvt;
use std::io;
use winapi::um::profileapi::QueryPerformanceFrequency;
use winapi::um::winnt::LARGE_INTEGER;

pub fn perf_counter_frequency() -> io::Result<u64> {
    unsafe {
        let mut frequency: LARGE_INTEGER = std::mem::zeroed();
        cvt(QueryPerformanceFrequency(&mut frequency))?;
        Ok(*frequency.QuadPart() as u64)
    }
}
