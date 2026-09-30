//! Statistics (SPEC §13.6).
//!
//! - Quantiles interpolate linearly between order statistics (Hyndman–Fan
//!   type 7), so the median of an even sample is the mean of the middle two.
//! - The CI for a median is the 2.5th and 97.5th percentiles of `B`
//!   bootstrap medians. Each resample draws n samples with replacement,
//!   from a ChaCha20 stream with a recorded seed.
//! - Bootstrap medians are kept in draw order, so that draw b of one
//!   configuration can be paired with draw b of another. Ratios and the Q3
//!   fit are computed draw by draw, which resamples each configuration
//!   independently.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub n: usize,
    pub median: f64,
    pub mean: f64,
    pub sd: f64,
    pub p95: f64,
    pub p99: f64,
    pub min: f64,
    pub max: f64,
    pub median_ci: (f64, f64),
}

/// Type-7 quantile of sorted data.
pub fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    assert!(!sorted.is_empty());
    let h = (sorted.len() - 1) as f64 * q;
    let lo = h.floor() as usize;
    let hi = h.ceil() as usize;
    sorted[lo] + (h - lo as f64) * (sorted[hi] - sorted[lo])
}

/// The median of `buf`, reordering it.
fn median_in_place(buf: &mut [u64]) -> f64 {
    let n = buf.len();
    let mid = n / 2;
    let (_, m, _) = buf.select_nth_unstable(mid);
    let m = *m as f64;
    if n % 2 == 1 {
        m
    } else {
        // The largest of the lower half.
        let lower = *buf[..mid].iter().max().expect("n ≥ 2") as f64;
        (lower + m) / 2.0
    }
}

/// `b` bootstrap medians of `samples`, in draw order.
pub fn bootstrap_medians(samples: &[u64], b: usize, seed: u64) -> Vec<f64> {
    let n = samples.len();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut buf = vec![0u64; n];
    (0..b)
        .map(|_| {
            for x in buf.iter_mut() {
                *x = samples[(rng.next_u64() % n as u64) as usize];
            }
            median_in_place(&mut buf)
        })
        .collect()
}

/// The 95% percentile interval of a bootstrap distribution.
pub fn interval(draws: &[f64]) -> (f64, f64) {
    let mut s: Vec<f64> = draws.iter().copied().filter(|x| x.is_finite()).collect();
    s.sort_by(f64::total_cmp);
    (quantile_sorted(&s, 0.025), quantile_sorted(&s, 0.975))
}

pub fn summarize(samples: &[u64], draws: &[f64]) -> Summary {
    let mut sorted: Vec<f64> = samples.iter().map(|&x| x as f64).collect();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let var = if n > 1 {
        sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    Summary {
        n,
        median: quantile_sorted(&sorted, 0.5),
        mean,
        sd: var.sqrt(),
        p95: quantile_sorted(&sorted, 0.95),
        p99: quantile_sorted(&sorted, 0.99),
        min: sorted[0],
        max: sorted[n - 1],
        median_ci: interval(draws),
    }
}

/// A ratio of two medians, with its bootstrap interval.
#[derive(Clone, Debug, Serialize)]
pub struct Ratio {
    pub value: f64,
    pub ci: (f64, f64),
}

pub fn ratio(a: &Summary, a_draws: &[f64], b: &Summary, b_draws: &[f64]) -> Ratio {
    let draws: Vec<f64> = a_draws.iter().zip(b_draws).map(|(x, y)| x / y).collect();
    Ratio {
        value: a.median / b.median,
        ci: interval(&draws),
    }
}

/// Ordinary least squares, y = α + β·x.
pub fn ols(x: &[f64], y: &[f64]) -> (f64, f64, f64) {
    let n = x.len() as f64;
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;
    let sxy: f64 = x.iter().zip(y).map(|(a, b)| (a - mx) * (b - my)).sum();
    let sxx: f64 = x.iter().map(|a| (a - mx).powi(2)).sum();
    let beta = sxy / sxx;
    let alpha = my - beta * mx;
    let ss_res: f64 = x
        .iter()
        .zip(y)
        .map(|(a, b)| (b - alpha - beta * a).powi(2))
        .sum();
    let ss_tot: f64 = y.iter().map(|b| (b - my).powi(2)).sum();
    let r2 = if ss_tot > 0.0 {
        1.0 - ss_res / ss_tot
    } else {
        1.0
    };
    (alpha, beta, r2)
}

/// The Q3 fit (SPEC §13.6): OLS over the per-N medians, with bootstrap
/// intervals for α, β and 10β/α from the per-N bootstrap medians, paired
/// by draw.
#[derive(Clone, Debug, Serialize)]
pub struct Fit {
    pub ns: Vec<f64>,
    pub medians: Vec<f64>,
    pub alpha: f64,
    pub beta: f64,
    pub r2: f64,
    pub residuals: Vec<f64>,
    pub alpha_ci: (f64, f64),
    pub beta_ci: (f64, f64),
    pub ten_beta_over_alpha: f64,
    pub ten_beta_over_alpha_ci: (f64, f64),
}

pub fn fit(ns: &[f64], medians: &[f64], draws: &[&[f64]]) -> Fit {
    let (alpha, beta, r2) = ols(ns, medians);
    let residuals = ns
        .iter()
        .zip(medians)
        .map(|(x, y)| y - alpha - beta * x)
        .collect();
    let b = draws.iter().map(|d| d.len()).min().unwrap_or(0);
    let mut alphas = Vec::with_capacity(b);
    let mut betas = Vec::with_capacity(b);
    let mut ratios = Vec::with_capacity(b);
    for i in 0..b {
        let y: Vec<f64> = draws.iter().map(|d| d[i]).collect();
        let (a, bt, _) = ols(ns, &y);
        alphas.push(a);
        betas.push(bt);
        ratios.push(10.0 * bt / a);
    }
    Fit {
        ns: ns.to_vec(),
        medians: medians.to_vec(),
        alpha,
        beta,
        r2,
        residuals,
        alpha_ci: interval(&alphas),
        beta_ci: interval(&betas),
        ten_beta_over_alpha: 10.0 * beta / alpha,
        ten_beta_over_alpha_ci: interval(&ratios),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_and_medians() {
        let s = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(quantile_sorted(&s, 0.5), 2.5);
        assert_eq!(quantile_sorted(&s, 0.0), 1.0);
        assert_eq!(quantile_sorted(&s, 1.0), 4.0);
        assert_eq!(median_in_place(&mut [5, 1, 3]), 3.0);
        assert_eq!(median_in_place(&mut [4, 1, 3, 2]), 2.5);
    }

    #[test]
    fn ols_recovers_a_line() {
        let x = [1.0, 2.0, 3.0, 5.0, 10.0];
        let y: Vec<f64> = x.iter().map(|v| 100.0 + 7.0 * v).collect();
        let (a, b, r2) = ols(&x, &y);
        assert!((a - 100.0).abs() < 1e-9 && (b - 7.0).abs() < 1e-9 && (r2 - 1.0).abs() < 1e-12);
    }

    #[test]
    fn bootstrap_is_reproducible_and_brackets_the_median() {
        let samples: Vec<u64> = (0..1001).map(|i| 1000 + (i * 7919) % 1000).collect();
        let a = bootstrap_medians(&samples, 500, 1);
        assert_eq!(a, bootstrap_medians(&samples, 500, 1));
        let s = summarize(&samples, &a);
        assert!(s.median_ci.0 <= s.median && s.median <= s.median_ci.1);
    }
}
