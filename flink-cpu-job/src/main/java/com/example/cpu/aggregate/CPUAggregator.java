package com.example.cpu.aggregate;

import com.example.cpu.model.CPUMetric;
import org.apache.flink.streaming.api.functions.windowing.WindowFunction;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CPUAggregator implements WindowFunction<CPUMetric, String, String, TimeWindow> {
    private static final Logger LOG = LoggerFactory.getLogger(CPUAggregator.class);

    @Override
    public void apply(String key, TimeWindow window, Iterable<CPUMetric> input, Collector<String> out) throws Exception {
        double totalCpu = 0.0;
        int count = 0;
        double maxCpu = 0.0;
        String topMethod = "";

        for (CPUMetric metric : input) {
            totalCpu += metric.getCpuUsage();
            count++;
            if (metric.getCpuUsage() > maxCpu) {
                maxCpu = metric.getCpuUsage();
                topMethod = metric.getMethod();
            }
        }

        double avgCpu = count > 0 ? totalCpu / count : 0.0;
        String result = String.format(
            "Window [%d-%d] Avg CPU: %.2f%% Max CPU: %.2f%% Top Method: %s",
            window.getStart(), window.getEnd(), avgCpu, maxCpu, topMethod
        );

        LOG.info(result);
        out.collect(result);
    }
}