use std::collections::{HashMap, VecDeque};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};

use chrono::Utc;
use parking_lot::Mutex;
use serde::Serialize;

const WINDOW_60S_MS: i64 = 60_000;
const WINDOW_5M_MS: i64 = 5 * 60_000;
const TOP_MODEL_LIMIT: usize = 5;

pub type SharedTrafficMetrics = Arc<TrafficMetrics>;

static GLOBAL_TRAFFIC_METRICS: OnceLock<SharedTrafficMetrics> = OnceLock::new();

pub fn global_traffic_metrics() -> SharedTrafficMetrics {
    GLOBAL_TRAFFIC_METRICS
        .get_or_init(|| Arc::new(TrafficMetrics::default()))
        .clone()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelTrafficSnapshot {
    pub model: String,
    #[serde(rename = "requestsLast5m")]
    pub requests_last_5m: u64,
    pub current_concurrent: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficMetricsSnapshot {
    pub current_concurrent: u64,
    pub peak_concurrent_60s: u64,
    #[serde(rename = "peakConcurrent5m")]
    pub peak_concurrent_5m: u64,
    pub requests_last_60s: u64,
    #[serde(rename = "requestsLast5m")]
    pub requests_last_5m: u64,
    #[serde(rename = "streamingRequestsLast5m")]
    pub streaming_requests_last_5m: u64,
    pub qps_last_60s: f64,
    #[serde(rename = "qpsLast5m")]
    pub qps_last_5m: f64,
    #[serde(rename = "topModelsLast5m")]
    pub top_models_last_5m: Vec<ModelTrafficSnapshot>,
    pub total_started: u64,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
struct TrafficEvent {
    ts_ms: i64,
    model: String,
    is_stream: bool,
    concurrent_after_start: u64,
}

#[derive(Default)]
struct TrafficInner {
    events: VecDeque<TrafficEvent>,
    current_by_model: HashMap<String, u64>,
}

#[derive(Default)]
pub struct TrafficMetrics {
    current_concurrent: AtomicU64,
    total_started: AtomicU64,
    inner: Mutex<TrafficInner>,
}

impl TrafficMetrics {
    pub fn begin(self: &Arc<Self>, model: &str, is_stream: bool) -> TrafficRequestGuard {
        let now_ms = Utc::now().timestamp_millis();
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_started.fetch_add(1, Ordering::Relaxed);

        {
            let mut inner = self.inner.lock();
            prune_events(&mut inner, now_ms - WINDOW_5M_MS);
            inner.events.push_back(TrafficEvent {
                ts_ms: now_ms,
                model: model.to_string(),
                is_stream,
                concurrent_after_start: current,
            });
            *inner.current_by_model.entry(model.to_string()).or_insert(0) += 1;
        }

        TrafficRequestGuard {
            metrics: self.clone(),
            model: model.to_string(),
        }
    }

    pub fn snapshot(&self) -> TrafficMetricsSnapshot {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let cutoff_60s = now_ms - WINDOW_60S_MS;
        let cutoff_5m = now_ms - WINDOW_5M_MS;

        let (
            requests_last_60s,
            requests_last_5m,
            streaming_requests_last_5m,
            peak_concurrent_60s,
            peak_concurrent_5m,
            top_models_last_5m,
        ) = {
            let mut inner = self.inner.lock();
            prune_events(&mut inner, cutoff_5m);

            let current_by_model = inner.current_by_model.clone();
            let mut requests_last_60s = 0u64;
            let mut requests_last_5m = 0u64;
            let mut streaming_requests_last_5m = 0u64;
            let mut peak_concurrent_60s = 0u64;
            let mut peak_concurrent_5m = 0u64;
            let mut by_model: HashMap<String, u64> = HashMap::new();

            for event in &inner.events {
                if event.ts_ms >= cutoff_5m {
                    requests_last_5m += 1;
                    if event.is_stream {
                        streaming_requests_last_5m += 1;
                    }
                    peak_concurrent_5m =
                        peak_concurrent_5m.max(event.concurrent_after_start);
                    *by_model.entry(event.model.clone()).or_insert(0) += 1;
                }
                if event.ts_ms >= cutoff_60s {
                    requests_last_60s += 1;
                    peak_concurrent_60s =
                        peak_concurrent_60s.max(event.concurrent_after_start);
                }
            }

            let mut top_models: Vec<_> = by_model
                .into_iter()
                .map(|(model, requests_last_5m)| ModelTrafficSnapshot {
                    current_concurrent: current_by_model.get(&model).copied().unwrap_or(0),
                    model,
                    requests_last_5m,
                })
                .collect();
            top_models.sort_by(|a, b| {
                b.requests_last_5m
                    .cmp(&a.requests_last_5m)
                    .then_with(|| a.model.cmp(&b.model))
            });
            top_models.truncate(TOP_MODEL_LIMIT);

            (
                requests_last_60s,
                requests_last_5m,
                streaming_requests_last_5m,
                peak_concurrent_60s,
                peak_concurrent_5m,
                top_models,
            )
        };

        let current_concurrent = self.current_concurrent.load(Ordering::Relaxed);

        TrafficMetricsSnapshot {
            current_concurrent,
            peak_concurrent_60s: peak_concurrent_60s.max(current_concurrent),
            peak_concurrent_5m: peak_concurrent_5m.max(current_concurrent),
            requests_last_60s,
            requests_last_5m,
            streaming_requests_last_5m,
            qps_last_60s: requests_last_60s as f64 / 60.0,
            qps_last_5m: requests_last_5m as f64 / 300.0,
            top_models_last_5m,
            total_started: self.total_started.load(Ordering::Relaxed),
            updated_at: now.to_rfc3339(),
        }
    }

    fn finish(&self, model: &str) {
        let _ = self.current_concurrent.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(1)),
        );

        let mut inner = self.inner.lock();
        if let Some(count) = inner.current_by_model.get_mut(model) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.current_by_model.remove(model);
            }
        }
    }
}

pub struct TrafficRequestGuard {
    metrics: SharedTrafficMetrics,
    model: String,
}

impl Drop for TrafficRequestGuard {
    fn drop(&mut self) {
        self.metrics.finish(&self.model);
    }
}

fn prune_events(inner: &mut TrafficInner, cutoff_ms: i64) {
    while inner
        .events
        .front()
        .map(|event| event.ts_ms < cutoff_ms)
        .unwrap_or(false)
    {
        inner.events.pop_front();
    }
}
