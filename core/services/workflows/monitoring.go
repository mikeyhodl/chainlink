package workflows

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	monutils "github.com/smartcontractkit/chainlink/v2/core/monitoring"
)

// em AKA "engine metrics" is to locally scope these instruments to avoid
// data races in testing
type engineMetrics struct {
	registerTriggerFailureCounter      metric.Int64Counter
	triggerWorkflowStarterErrorCounter metric.Int64Counter
	workflowsRunningGauge              metric.Int64Gauge
	capabilityInvocationCounter        metric.Int64Counter
	capabilityFailureCounter           metric.Int64Counter
	workflowRegisteredCounter          metric.Int64Counter
	workflowUnregisteredCounter        metric.Int64Counter
	workflowExecutionLatencyGauge      metric.Int64Gauge // ms
	workflowStepErrorCounter           metric.Int64Counter
	workflowInitializationCounter      metric.Int64Counter
	engineHeartbeatCounter             metric.Int64Counter
	workflowCompletedDurationSeconds   metric.Int64Histogram
	workflowEarlyExitDurationSeconds   metric.Int64Histogram
	workflowErrorDurationSeconds       metric.Int64Histogram
	workflowTimeoutDurationSeconds     metric.Int64Histogram
	workflowStepDurationSeconds        metric.Int64Histogram
}

func initMonitoringResources() (em *engineMetrics, err error) {
	em = &engineMetrics{}
	em.registerTriggerFailureCounter, err = beholder.GetMeter().Int64Counter("platform_engine_registertrigger_failures")
	if err != nil {
		return nil, fmt.Errorf("failed to register trigger failure counter: %w", err)
	}

	em.triggerWorkflowStarterErrorCounter, err = beholder.GetMeter().Int64Counter("platform_engine_triggerworkflow_starter_errors")
	if err != nil {
		return nil, fmt.Errorf("failed to register trigger workflow starter error counter: %w", err)
	}

	em.workflowsRunningGauge, err = beholder.GetMeter().Int64Gauge("platform_engine_workflow_count")
	if err != nil {
		return nil, fmt.Errorf("failed to register workflows running gauge: %w", err)
	}

	em.capabilityInvocationCounter, err = beholder.GetMeter().Int64Counter("platform_engine_capabilities_count")
	if err != nil {
		return nil, fmt.Errorf("failed to register capability invocation counter: %w", err)
	}

	em.capabilityFailureCounter, err = beholder.GetMeter().Int64Counter("platform_engine_capabilities_failures")
	if err != nil {
		return nil, fmt.Errorf("failed to register capability failure counter: %w", err)
	}

	em.workflowRegisteredCounter, err = beholder.GetMeter().Int64Counter("platform_engine_workflow_registered_count")
	if err != nil {
		return nil, fmt.Errorf("failed to register workflow registered counter: %w", err)
	}

	em.workflowUnregisteredCounter, err = beholder.GetMeter().Int64Counter("platform_engine_workflow_unregistered_count")
	if err != nil {
		return nil, fmt.Errorf("failed to register workflow unregistered counter: %w", err)
	}

	em.workflowExecutionLatencyGauge, err = beholder.GetMeter().Int64Gauge(
		"platform_engine_workflow_time",
		metric.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("failed to register workflow execution latency gauge: %w", err)
	}

	em.workflowInitializationCounter, err = beholder.GetMeter().Int64Counter("platform_engine_workflow_initializations")
	if err != nil {
		return nil, fmt.Errorf("failed to register workflow initialization counter: %w", err)
	}

	em.workflowStepErrorCounter, err = beholder.GetMeter().Int64Counter("platform_engine_workflow_errors")
	if err != nil {
		return nil, fmt.Errorf("failed to register workflow step error counter: %w", err)
	}

	em.engineHeartbeatCounter, err = beholder.GetMeter().Int64Counter("platform_engine_heartbeat")
	if err != nil {
		return nil, fmt.Errorf("failed to register engine heartbeat counter: %w", err)
	}

	em.workflowCompletedDurationSeconds, err = beholder.GetMeter().Int64Histogram(
		"platform_engine_workflow_completed_time_seconds",
		metric.WithDescription("Distribution of completed execution latencies"),
		metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register completed duration histogram: %w", err)
	}

	em.workflowEarlyExitDurationSeconds, err = beholder.GetMeter().Int64Histogram(
		"platform_engine_workflow_earlyexit_time_seconds",
		metric.WithDescription("Distribution of earlyexit execution latencies"),
		metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register early exit duration histogram: %w", err)
	}

	em.workflowErrorDurationSeconds, err = beholder.GetMeter().Int64Histogram(
		"platform_engine_workflow_error_time_seconds",
		metric.WithDescription("Distribution of error execution latencies"),
		metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register error duration histogram: %w", err)
	}

	em.workflowTimeoutDurationSeconds, err = beholder.GetMeter().Int64Histogram(
		"platform_engine_workflow_timeout_time_seconds",
		metric.WithDescription("Distribution of timeout execution latencies"),
		metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register timeout duration histogram: %w", err)
	}

	em.workflowStepDurationSeconds, err = beholder.GetMeter().Int64Histogram(
		"platform_engine_workflow_step_time_seconds",
		metric.WithDescription("Distribution of step execution times"),
		metric.WithUnit("seconds"))
	if err != nil {
		return nil, fmt.Errorf("failed to register step execution time histogram: %w", err)
	}

	return em, nil
}

// workflowsMetricLabeler wraps monitoring.MetricsLabeler to provide workflow specific utilities
// for monitoring resources
type workflowsMetricLabeler struct {
	metrics.Labeler
	em engineMetrics
}

func (c workflowsMetricLabeler) with(keyValues ...string) workflowsMetricLabeler {
	return workflowsMetricLabeler{c.With(keyValues...), c.em}
}

func (c workflowsMetricLabeler) incrementRegisterTriggerFailureCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.registerTriggerFailureCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementTriggerWorkflowStarterErrorCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.triggerWorkflowStarterErrorCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementCapabilityInvocationCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.capabilityInvocationCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowExecutionLatencyGauge(ctx context.Context, val int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowExecutionLatencyGauge.Record(ctx, val, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementTotalWorkflowStepErrorsCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowStepErrorCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateTotalWorkflowsGauge(ctx context.Context, val int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowsRunningGauge.Record(ctx, val, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementEngineHeartbeatCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.engineHeartbeatCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementCapabilityFailureCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.capabilityFailureCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementWorkflowRegisteredCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowRegisteredCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementWorkflowUnregisteredCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowUnregisteredCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) incrementWorkflowInitializationCounter(ctx context.Context) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowInitializationCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowCompletedDurationHistogram(ctx context.Context, duration int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowCompletedDurationSeconds.Record(ctx, duration, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowEarlyExitDurationHistogram(ctx context.Context, duration int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowEarlyExitDurationSeconds.Record(ctx, duration, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowErrorDurationHistogram(ctx context.Context, duration int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowErrorDurationSeconds.Record(ctx, duration, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowTimeoutDurationHistogram(ctx context.Context, duration int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowTimeoutDurationSeconds.Record(ctx, duration, metric.WithAttributes(otelLabels...))
}

func (c workflowsMetricLabeler) updateWorkflowStepDurationHistogram(ctx context.Context, duration int64) {
	otelLabels := monutils.KvMapToOtelAttributes(c.Labels)
	c.em.workflowStepDurationSeconds.Record(ctx, duration, metric.WithAttributes(otelLabels...))
}