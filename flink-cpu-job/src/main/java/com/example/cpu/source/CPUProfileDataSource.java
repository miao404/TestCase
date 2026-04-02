package com.example.cpu.source;

import com.example.cpu.model.CPUMetric;
import org.apache.flink.streaming.api.functions.source.RichParallelSourceFunction;

public class CPUProfileDataSource extends RichParallelSourceFunction<CPUMetric> {
    private volatile boolean isRunning = true;

    @Override
    public void run(SourceContext<CPUMetric> ctx) throws Exception {
        int taskId = getRuntimeContext().getIndexOfThisSubtask();
        long recordCount = 0;

        while (isRunning && recordCount < 1000000) {
            String threadName = "flink-cpu-thread-" + taskId;
            double cpuUsage = Math.random() * 100;
            long timestamp = System.currentTimeMillis();
            String method = selectMethod(recordCount);

            CPUMetric metric = new CPUMetric(threadName, cpuUsage, timestamp, method);
            ctx.collect(metric);

            recordCount++;
            Thread.sleep(10);
        }
    }

    @Override
    public void cancel() {
        isRunning = false;
    }

    private String selectMethod(long recordCount) {
        String[] methods = {
            "PSPromotionManager::drain_stacks_depth",
            "oopDesc::copy_to_survivor_space",
            "StringTable::unlink_or_oops_do",
            "os::javaTimeNanos",
            "clock_gettime",
            "SharedRuntime::complete_monitor_unlocking_C",
            "ObjectMonitor::exit",
            "foward_copy_longs"
        };
        return methods[(int)(recordCount % methods.length)];
    }
}