package com.example.cpu.model;

import java.io.Serializable;

public class CPUMetric implements Serializable {
    private static final long serialVersionUID = 1L;

    private String threadName;
    private double cpuUsage;
    private long timestamp;
    private String method;

    public CPUMetric() {}

    public CPUMetric(String threadName, double cpuUsage, long timestamp, String method) {
        this.threadName = threadName;
        this.cpuUsage = cpuUsage;
        this.timestamp = timestamp;
        this.method = method;
    }

    public String getThreadName() {
        return threadName;
    }

    public void setThreadName(String threadName) {
        this.threadName = threadName;
    }

    public double getCpuUsage() {
        return cpuUsage;
    }

    public void setCpuUsage(double cpuUsage) {
        this.cpuUsage = cpuUsage;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    @Override
    public String toString() {
        return "CPUMetric{" +
                "threadName='" + threadName + '\'' +
                ", cpuUsage=" + cpuUsage +
                ", timestamp=" + timestamp +
                ", method='" + method + '\'' +
                '}';
    }
}