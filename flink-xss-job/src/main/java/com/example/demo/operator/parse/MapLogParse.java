package com.example.demo.operator.parse;

import com.example.demo.record.ParseResult;
import org.apache.flink.api.common.functions.RichMapFunction;
import org.apache.flink.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 日志解析 MapFunction — 将 Kafka 原始消息映射为 ParseResult。
 * 对应火焰图中:
 *   org/apache/flink/streaming/api/operators/StreamMap.processElement
 *     → com/meituan/rc/zeus/nearline/flink/operator/parse/MapLogParse.map
 *       → com/meituan/rc/zeus/nearline/flink/operator/parse/CommonParse.parseValue
 *
 * 同时还涉及火焰图中:
 *   AbstractLogParse.checkWholeDial / setUpUdfThreadInfo / clearUdfThreadInfo / setProfierData
 */
public class MapLogParse extends RichMapFunction<String, ParseResult> {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(MapLogParse.class);

    private transient CommonParse commonParse;

    @Override
    public void open(Configuration parameters) throws Exception {
        super.open(parameters);
        commonParse = new CommonParse();
        setUpUdfThreadInfo();
        LOG.info("MapLogParse opened");
    }

    /**
     * 核心 map 方法 — 解析原始日志。
     * 对应火焰图:
     *   MapLogParse.map → CommonParse.parseValue
     */
    @Override
    public ParseResult map(String rawLog) throws Exception {
        try {
            setUpUdfThreadInfo();
            checkWholeDial();
            ParseResult result = commonParse.parseValue(rawLog);
            setProfierData(result);
            return result;
        } catch (Exception e) {
            LOG.error("MapLogParse failed to parse log: {}", e.getMessage());
            ParseResult fallback = new ParseResult();
            fallback.setRequestBody(rawLog);
            fallback.setEventTime(System.currentTimeMillis());
            return fallback;
        } finally {
            clearUdfThreadInfo();
        }
    }

    /**
     * 设置 UDF 线程信息（用于追踪和诊断）。
     * 对应火焰图: AbstractLogParse.setUpUdfThreadInfo
     */
    private void setUpUdfThreadInfo() {
        Thread.currentThread().setName("xss-map-log-parse");
    }

    /**
     * 清除 UDF 线程信息。
     * 对应火焰图: AbstractLogParse.clearUdfThreadInfo
     */
    private void clearUdfThreadInfo() {
        // 清理线程局部变量
    }

    /**
     * 全量拨测检查。
     * 对应火焰图: AbstractLogParse.checkWholeDial
     */
    private void checkWholeDial() {
        // 拨测逻辑（在生产环境中检查是否需要全量拨测）
    }

    /**
     * 设置 Profiler 数据。
     * 对应火焰图: AbstractLogParse.setProfierData
     */
    private void setProfierData(ParseResult result) {
        // 性能剖析数据采集
    }
}
