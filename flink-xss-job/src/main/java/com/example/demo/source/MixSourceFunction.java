package com.example.demo.source;

import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.functions.source.RichParallelSourceFunction;
import org.apache.flink.streaming.connectors.kafka.FlinkKafkaConsumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * 混合数据源 — 从 Kafka 消费原始流量日志。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/job/MixSourceFunction.run
 *     → org/apache/flink/streaming/connectors/kafka/FlinkKafkaConsumerBase.run
 *       → org/apache/flink/streaming/connectors/kafka/FlinkKafkaConsumerBase.runWithPartitionDiscovery
 *         → org/apache/flink/streaming/connectors/kafka/internals/Kafka010Fetcher.runFetchLoop
 *
 * 在实际部署中，此类封装了 FlinkKafkaConsumer 的创建与运行；
 * 这里简化为直接委托给 FlinkKafkaConsumer，保持火焰图中的调用链关系。
 */
public class MixSourceFunction extends RichParallelSourceFunction<String> {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(MixSourceFunction.class);

    private final String topic;
    private final Properties kafkaProps;
    private transient FlinkKafkaConsumer<String> kafkaConsumer;
    private volatile boolean running = true;

    public MixSourceFunction(String topic, Properties kafkaProps) {
        this.topic = topic;
        this.kafkaProps = kafkaProps;
    }

    @Override
    public void open(Configuration parameters) throws Exception {
        super.open(parameters);
        kafkaConsumer = new FlinkKafkaConsumer<>(topic, new SimpleStringSchema(), kafkaProps);
        kafkaConsumer.setRuntimeContext(getRuntimeContext());
        kafkaConsumer.open(parameters);
        LOG.info("MixSourceFunction opened for topic: {}", topic);
    }

    /**
     * 核心运行方法 — 委托给 FlinkKafkaConsumer。
     * 对应火焰图:
     *   MixSourceFunction.run
     *     → FlinkKafkaConsumerBase.run
     *       → FlinkKafkaConsumerBase.runWithPartitionDiscovery
     *         → Kafka010Fetcher.runFetchLoop
     *           → Kafka010Fetcher.partitionConsumerRecordsHandler
     *             → AbstractFetcher.emitRecordsWithTimestamps
     */
    @Override
    public void run(SourceContext<String> ctx) throws Exception {
        kafkaConsumer.run(ctx);
    }

    @Override
    public void cancel() {
        running = false;
        if (kafkaConsumer != null) {
            kafkaConsumer.cancel();
        }
    }

    @Override
    public void close() throws Exception {
        if (kafkaConsumer != null) {
            kafkaConsumer.close();
        }
        super.close();
    }
}
