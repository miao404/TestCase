package com.example.cpu.parse;

import com.example.cpu.model.CPUMetric;
import com.example.cpu.model.ParseResult;

public class LogParser {
    public static ParseResult parse(String logLine) {
        if (logLine == null || logLine.isEmpty()) {
            return null;
        }

        String[] parts = logLine.split("\\|");
        if (parts.length < 3) {
            return null;
        }

        String rawData = parts[0];
        String timestamp = parts.length > 1 ? parts[1] : String.valueOf(System.currentTimeMillis());
        String source = parts.length > 2 ? parts[2] : "unknown";

        return new ParseResult(rawData, timestamp, source);
    }

    public static CPUMetric parseMetricFromFlameGraph(String frameInfo) {
        if (frameInfo == null || frameInfo.isEmpty()) {
            return null;
        }

        String[] components = frameInfo.split(",");
        if (components.length < 4) {
            return null;
        }

        String threadName = components[0].trim();
        double cpuUsage = Double.parseDouble(components[1].trim());
        long timestamp = Long.parseLong(components[2].trim());
        String method = components[3].trim();

        return new CPUMetric(threadName, cpuUsage, timestamp, method);
    }
}