//! Thermal state, from `pmset -g therm`, read before and after every
//! configuration (frozen plan §5).
//!
//! On Intel Macs the output carries `CPU_Speed_Limit = n`. On this machine
//! (Apple Silicon) it carries only notes, such as "No thermal warning level
//! has been recorded". The rule, fixed before any measurement: a reading is
//! **throttled** if it reports a CPU speed limit below 100, or records a
//! thermal or performance warning level. A configuration with a throttled
//! reading before or after it is re-run after the main runs, and logged in
//! `BENCH_LOG.md` whatever its result.

use std::process::Command;

use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Reading {
    /// `CPU_Speed_Limit`, if reported.
    pub cpu_speed_limit: Option<u32>,
    /// A recorded thermal warning level line, if any.
    pub thermal_warning: Option<String>,
    /// A recorded performance warning level line, if any.
    pub performance_warning: Option<String>,
    /// Whether `pmset` could be run at all.
    pub available: bool,
}

impl Reading {
    pub fn throttled(&self) -> bool {
        self.cpu_speed_limit.is_some_and(|l| l < 100)
            || self.thermal_warning.is_some()
            || self.performance_warning.is_some()
    }

    /// CSV fields: speed limit, thermal warning, performance warning,
    /// throttled.
    pub fn fields(&self) -> [String; 4] {
        [
            self.cpu_speed_limit
                .map_or("not reported".into(), |l| l.to_string()),
            self.thermal_warning
                .clone()
                .unwrap_or_else(|| "none".into()),
            self.performance_warning
                .clone()
                .unwrap_or_else(|| "none".into()),
            self.throttled().to_string(),
        ]
    }
}

pub fn parse(out: &str) -> Reading {
    let mut r = Reading {
        available: true,
        ..Reading::default()
    };
    for line in out.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = line.strip_prefix("CPU_Speed_Limit") {
            r.cpu_speed_limit = v.trim_start_matches([' ', '\t', '=']).trim().parse().ok();
        } else if lower.starts_with("note: no ") {
            // "Note: No … has been recorded".
        } else if lower.contains("thermal warning level") {
            r.thermal_warning = Some(line.to_owned());
        } else if lower.contains("performance warning level") {
            r.performance_warning = Some(line.to_owned());
        }
    }
    r
}

pub fn read() -> Reading {
    match Command::new("pmset").args(["-g", "therm"]).output() {
        Ok(o) if o.status.success() => parse(&String::from_utf8_lossy(&o.stdout)),
        _ => Reading::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_silicon_notes_are_not_throttling() {
        let r = parse(
            "Note: No thermal warning level has been recorded\nNote: No performance warning level has been recorded\nNote: No CPU power status has been recorded\n",
        );
        assert!(!r.throttled());
        assert_eq!(r.cpu_speed_limit, None);
    }

    #[test]
    fn intel_speed_limit_and_warnings() {
        let r = parse(
            "CPU_Scheduler_Limit \t= 100\nCPU_Available_CPUs \t= 8\nCPU_Speed_Limit \t= 72\n",
        );
        assert_eq!(r.cpu_speed_limit, Some(72));
        assert!(r.throttled());
        assert!(!parse("CPU_Speed_Limit \t= 100\n").throttled());
        assert!(parse("Thermal warning level set to 2.\n").throttled());
        assert!(parse("Performance warning level: 1\n").throttled());
    }
}
