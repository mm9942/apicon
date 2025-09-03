use std::cmp::min;

/// Dual exponentially weighted moving average tracking short and long trends.
#[derive(Debug, Default)]
pub struct DualEwma {
    short: f64,
    long: f64,
}

impl DualEwma {
    /// Record a new sample in milliseconds along with contextual metrics.
    /// `volume` is recent request count and `variance`/`mean` come from traffic metrics.
    pub fn record(&mut self, sample: f64, volume: usize, mean: f64, variance: f64) {
        // Filter extreme outliers using 3-sigma winsorization.
        let sd = variance.sqrt();
        let clipped = if sd > 0.0 {
            let lower = mean - 3.0 * sd;
            let upper = mean + 3.0 * sd;
            sample.clamp(lower, upper)
        } else {
            sample
        };

        // Base alphas for short/long term.
        let mut alpha_short = 0.5;
        let mut alpha_long = 0.05;

        // Reduce alpha when volume is high.
        if volume > 20 {
            let factor = min(volume, 100) as f64 / 100.0;
            alpha_short *= 1.0 - 0.5 * factor;
            alpha_long *= 1.0 - 0.8 * factor;
        }

        // Further reduce when variance is low.
        if sd < 1.0 {
            alpha_short *= 0.5;
            alpha_long *= 0.5;
        }

        // Increase alpha on sudden spikes.
        if sd > 0.0 && (clipped - mean).abs() > 3.0 * sd {
            alpha_short = 0.8;
            alpha_long = 0.1;
        }

        if self.short == 0.0 {
            self.short = clipped;
        } else {
            self.short = alpha_short * clipped + (1.0 - alpha_short) * self.short;
        }

        if self.long == 0.0 {
            self.long = clipped;
        } else {
            self.long = alpha_long * clipped + (1.0 - alpha_long) * self.long;
        }
    }

    /// Ratio between short-term and long-term trends.
    pub fn ratio(&self) -> f64 {
        if self.long == 0.0 {
            1.0
        } else {
            self.short / self.long
        }
    }

    pub(crate) fn short(&self) -> f64 {
        self.short
    }

}
