package com.example.cpu.process;

import com.example.cpu.model.CPUMetric;
import org.apache.flink.streaming.api.functions.ProcessFunction;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CPUProcessFunction extends ProcessFunction<CPUMetric, CPUMetric> {
    private static final Logger LOG = LoggerFactory.getLogger(CPUProcessFunction.class);

    @Override
    public void processElement(CPUMetric value, Context ctx, Collector<CPUMetric> out) throws Exception {
        try {
            if (value.getCpuUsage() > 50.0) {
                LOG.info("High CPU usage detected: {} for method: {}", value.getCpuUsage(), value.getMethod());
            }
            out.collect(value);
        } catch (Exception e) {
            LOG.error("Error processing CPU metric: {}", e.getMessage());
        }
    }
}