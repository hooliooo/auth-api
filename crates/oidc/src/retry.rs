//! Retrying an operation that fails while what it depends on is still starting, with
//! exponential backoff.

use std::{future::Future, time::Duration};

/// Exponential backoff: the first wait, the longest wait, and the time after which no further
/// attempt starts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Backoff {
    /// The wait after the first failure.
    pub first: Duration,
    /// The longest wait; each wait doubles until it reaches this.
    pub max: Duration,
    /// No attempt starts after this much time since the first.
    pub give_up_after: Duration,
}

/// Runs `attempt` until it succeeds, fails with an error `is_transient` rejects, or the next
/// wait would end past `backoff.give_up_after`; then returns its last result. Each retry is
/// logged.
pub(crate) async fn retry_transient<T, E, F, Fut>(
    mut attempt: F,
    is_transient: impl Fn(&E) -> bool,
    backoff: Backoff,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let started = tokio::time::Instant::now();
    let mut delay = backoff.first;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error)
                if is_transient(&error) && started.elapsed() + delay <= backoff.give_up_after =>
            {
                tracing::warn!(%error, retry_in = ?delay, "attempt failed; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(backoff.max);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A short backoff: 1 s, doubling to 4 s, for up to 10 s.
    const TEST_BACKOFF: Backoff = Backoff {
        first: Duration::from_secs(1),
        max: Duration::from_secs(4),
        give_up_after: Duration::from_secs(10),
    };

    /// An attempt that fails with `transient` errors `failures` times, then succeeds; counts
    /// its calls in `calls`.
    async fn flaky(calls: &AtomicU32, failures: u32) -> Result<&'static str, (bool, u32)> {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= failures {
            Err((true, n))
        } else {
            Ok("ready")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_operation_that_succeeds_late_then_it_is_retried_with_growing_pauses() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let result = retry_transient(
            || async {
                flaky(&calls, 3)
                    .await
                    .map_err(|(_, n)| format!("attempt {n}"))
            },
            |_| true,
            TEST_BACKOFF,
        )
        .await;
        assert_eq!(result, Ok("ready"));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        // 1 s, 2 s, then 4 s between the four attempts.
        assert_eq!(started.elapsed(), Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_permanent_error_then_it_fails_at_once() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let result: Result<(), String> = retry_transient(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err("permanent".to_owned())
            },
            |_| false,
            TEST_BACKOFF,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_operation_that_never_succeeds_then_it_gives_up_with_the_last_error() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let result = retry_transient(
            || async {
                flaky(&calls, u32::MAX)
                    .await
                    .map_err(|(_, n)| format!("attempt {n}"))
            },
            |_| true,
            TEST_BACKOFF,
        )
        .await;
        // Waits of 1, 2 and 4 s end at 7 s; a further 4 s would pass 10 s, so attempt 4 is the
        // last.
        assert_eq!(result, Err("attempt 4".to_owned()));
        assert_eq!(started.elapsed(), Duration::from_secs(7));
    }
}
