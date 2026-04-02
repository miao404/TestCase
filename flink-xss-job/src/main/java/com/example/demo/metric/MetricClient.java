package com.example.demo.metric;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * 指标上报客户端 — 提供延迟统计和计数统计功能。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/metric/metricreporter/MetricClient
 *     .allowedReporter
 *     .delayMetricStatistic
 *     .endCountAndDelayMetricStatisticForCanvas
 *     .enterCountMetricStatisticForCanvas
 */
public class MetricClient implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(MetricClient.class);

    private static final MetricClient INSTANCE = new MetricClient();

    private MetricClient() {
    }

    public static MetricClient getInstance() {
        return INSTANCE;
    }

    /**
     * 进入计数统计（画布算子）。
     * 对应火焰图: MetricClient.enterCountMetricStatisticForCanvas
     */
    public void enterCountMetricStatisticForCanvas(String canvasId, String operatorId) {
        // 指标上报：算子进入计数
    }

    /**
     * 结束计数和延迟统计（画布算子）。
     * 对应火焰图: MetricClient.endCountAndDelayMetricStatisticForCanvas
     */
    public void endCountAndDelayMetricStatisticForCanvas(String canvasId, String operatorId, long startTime) {
        // 指标上报：算子处理延迟和计数
    }

    /**
     * 延迟指标统计。
     * 对应火焰图: MetricClient.delayMetricStatistic
     */
    public void delayMetricStatistic(String metricKey, long delay) {
        // 延迟指标上报
    }

    /**
     * 检查是否允许上报。
     * 对应火焰图: MetricClient.allowedReporter
     */
    public boolean allowedReporter() {
        return true;
    }
}
