package com.example.demo.job;

import com.example.demo.operator.canvas.CanvasDataSourceFunction;
import com.example.demo.operator.canvas.CanvasMergeFunction;
import com.example.demo.operator.canvas.CanvasUnionFunction;
import com.example.demo.operator.canvas.DataSourceFilter;
import com.example.demo.operator.parse.MapLogParse;
import com.example.demo.record.ParseResult;
import com.example.demo.source.MixSourceFunction;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.java.utils.ParameterTool;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.sink.SinkFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * XSS 检测 Flink 流处理作业 — 完整复现 work1.html 火焰图的调用栈。
 *
 * <h2>完整流水线（对应火焰图调用链）:</h2>
 * <pre>
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ 1. Source: SourceStreamTask$LegacySourceFunctionThread.run              │
 * │    → StreamSource.run                                                    │
 * │      → MixSourceFunction.run                                            │
 * │        → FlinkKafkaConsumerBase.run                                     │
 * │          → FlinkKafkaConsumerBase.runWithPartitionDiscovery              │
 * │            → Kafka010Fetcher.runFetchLoop                               │
 * │              → Kafka010Fetcher.partitionConsumerRecordsHandler           │
 * │                → AbstractFetcher.emitRecordsWithTimestamps              │
 * │                  → KafkaDeserializationSchemaWrapper.deserialize         │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 2. Map (Log Parse): StreamMap.processElement                            │
 * │    → MapLogParse.map                                                    │
 * │      → CommonParse.parseValue                                           │
 * │        → ObjectMapper.readTree (Jackson JSON)                           │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 3. Filter: StreamFilter.processElement                                  │
 * │    → AbstractDataSourceTransformer.lambda$transform (DataSourceFilter)  │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 4. Process (Canvas DataSource): ProcessOperator.processElement          │
 * │    → CanvasProcessFunction.processElement                               │
 * │      → CanvasDataSourceFunction.onProcessElement                        │
 * │        → handleDefaultSource                                            │
 * │          → ObjectMap.filterFieldAndBuildObjectMap                        │
 * │          → CanvasLogHandler.appendRequestBasicInfo                      │
 * │            → RequestUtil.genRequestId                                   │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 5. Process (Canvas Union): ProcessOperator.processElement               │
 * │    → CanvasProcessFunction.processElement                               │
 * │      → CanvasUnionFunction.onProcessElement                             │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 6. Process (Canvas Merge — XSS Detection): ProcessOperator              │
 * │    → CanvasProcessFunction.processElement                               │
 * │      → CanvasMergeFunction.onProcessElement                             │
 * │        → doBefore                                                       │
 * │        → doProcess                                                      │
 * │          → processIfElse → processRuleSet → routeRuleSet               │
 * │          → processCode ← 火焰图最大热点                                  │
 * │            → xss.process (W=16464, 31.4%)                               │
 * │              → detectXssInRequestBody (W=1632)                          │
 * │                → detectXss → extract → canonicalizeWithCount            │
 * │                  → decodeHtmlEntity / decodeUnicode / decodeUrl         │
 * │                → detectXssInExtractedData → detectXssCore               │
 * │              → detectXssInResponseBody (W=14473, 最大热点)               │
 * │                → detectXss → extract                                    │
 * │                  → parseJsonWhole → extractJsonValues                   │
 * │                  → parseJsonStream → handleTruncatedJson                │
 * │                  → parseFormDataStream                                  │
 * │                  → canonicalizeWithCount                                │
 * │                    → decodeHtmlEntity / decodeUrl / decodeUnicode       │
 * │                  → repairJsonClosing → repairMissingQuote               │
 * │                → detectXssInExtractedData → detectXssCore               │
 * │              → detectXssInUrl                                           │
 * │              → filterXssRisk                                            │
 * │          → processSplit / processDrop                                   │
 * │        → doAfter → queueSingleOutput                                   │
 * ├──────────────────────────────────────────────────────────────────────────┤
 * │ 7. Sink: StreamSink.processWatermark                                    │
 * │    → XssResultSink (输出检测结果)                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 * </pre>
 *
 * <h2>其他火焰图中观察到的后台线程:</h2>
 * <ul>
 *   <li>KafkaConsumerThreadMt — Kafka 消费者轮询线程</li>
 *   <li>SystemProcessingTimeService — 处理时间服务（Watermark 定时触发）</li>
 *   <li>MailboxProcessor — Flink Mailbox 事件循环</li>
 *   <li>MetricClient / KafkaReporter — 指标上报</li>
 *   <li>GCTaskThread — JVM 垃圾回收</li>
 *   <li>CompilerThread — JIT 编译</li>
 * </ul>
 */
public class XssDetectionJob {

    private static final Logger LOG = LoggerFactory.getLogger(XssDetectionJob.class);

    public static void main(String[] args) throws Exception {
        // 解析命令行参数
        ParameterTool params = ParameterTool.fromArgs(args);

        // Kafka 配置
        String kafkaBrokers = params.get("kafka.brokers", "localhost:9092");
        String kafkaTopic = params.get("kafka.topic", "xss-detection-input");
        String kafkaGroupId = params.get("kafka.group.id", "xss-detection-group");

        // XSS 检测配置
        int xssThreshold = params.getInt("xss.threshold", 60);
        String dataSourceId = params.get("datasource.id", "");

        // 需要保留的字段
        Set<String> retainFields = new HashSet<>(Arrays.asList(
                "url", "requestBody", "responseBody", "eventTime",
                "canvasId", "dataSourceId", "clientIp", "userAgent"
        ));

        // ===== 创建执行环境 =====
        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        env.getConfig().setGlobalJobParameters(params);

        // ===== 构建流水线 =====

        // 1. Source: Kafka 数据源
        //    火焰图: SourceStreamTask → StreamSource → MixSourceFunction → FlinkKafkaConsumerBase
        Properties kafkaProps = new Properties();
        kafkaProps.setProperty("bootstrap.servers", kafkaBrokers);
        kafkaProps.setProperty("group.id", kafkaGroupId);
        kafkaProps.setProperty("auto.offset.reset", "latest");

        DataStream<String> sourceStream = env
                .addSource(new MixSourceFunction(kafkaTopic, kafkaProps))
                .name("MixSource-Kafka")
                .uid("source-mix-kafka");

        // 2. Map: 日志解析
        //    火焰图: StreamMap.processElement → MapLogParse.map → CommonParse.parseValue
        SingleOutputStreamOperator<ParseResult> parsedStream = sourceStream
                .map(new MapLogParse())
                .name("MapLogParse")
                .uid("map-log-parse");

        // 3. Filter: 数据源过滤
        //    火焰图: StreamFilter.processElement → DataSourceFilter
        SingleOutputStreamOperator<ParseResult> filteredStream = parsedStream
                .filter(new DataSourceFilter(dataSourceId))
                .name("DataSourceFilter")
                .uid("filter-datasource");

        // 4. Process: 画布数据源处理
        //    火焰图: ProcessOperator → CanvasProcessFunction → CanvasDataSourceFunction
        SingleOutputStreamOperator<ParseResult> dataSourceStream = filteredStream
                .process(new CanvasDataSourceFunction("canvas-datasource-001", retainFields))
                .name("CanvasDataSource")
                .uid("process-canvas-datasource");

        // 5. Process: 画布合流
        //    火焰图: ProcessOperator → CanvasProcessFunction → CanvasUnionFunction
        SingleOutputStreamOperator<ParseResult> unionStream = dataSourceStream
                .process(new CanvasUnionFunction("canvas-union-001"))
                .name("CanvasUnion")
                .uid("process-canvas-union");

        // 6. Process: 画布合并 — XSS 检测（最大热点）
        //    火焰图: ProcessOperator → CanvasProcessFunction → CanvasMergeFunction
        //      → processCode → xss.process
        SingleOutputStreamOperator<ParseResult> mergeStream = unionStream
                .process(new CanvasMergeFunction("canvas-merge-001", xssThreshold))
                .name("CanvasMerge-XssDetection")
                .uid("process-canvas-merge-xss");

        // 7. Sink: 输出检测结果
        //    火焰图: StreamSink.processWatermark
        mergeStream.addSink(new XssResultSink())
                .name("XssResultSink")
                .uid("sink-xss-result");

        // ===== 提交作业 =====
        env.execute("XSS Detection Flink Job");
    }

    /**
     * XSS 检测结果输出 Sink。
     * 对应火焰图中 StreamSink 的实现。
     */
    static class XssResultSink implements SinkFunction<ParseResult> {

        private static final long serialVersionUID = 1L;
        private static final Logger SINK_LOG = LoggerFactory.getLogger(XssResultSink.class);

        @Override
        public void invoke(ParseResult value, Context context) throws Exception {
            // 输出检测结果（实际生产中可写入 Kafka / ES / 数据库）
            String xssDetected = value.getFields().getOrDefault("__xss_detected", "false").toString();
            String maxScore = value.getFields().getOrDefault("__xss_max_score", "0").toString();

            if ("true".equals(xssDetected)) {
                SINK_LOG.warn("XSS DETECTED! canvasId={}, url={}, maxScore={}",
                        value.getCanvasId(), value.getUrl(), maxScore);
            }
        }
    }
}
