package com.example.demo.operator.canvas;

import com.example.demo.record.ParseResult;
import org.apache.flink.api.common.functions.RichFilterFunction;
import org.apache.flink.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 数据源过滤器 — 过滤不符合条件的数据。
 * 对应火焰图中:
 *   org/apache/flink/streaming/api/operators/StreamFilter.processElement
 *     → AbstractDataSourceTransformer.lambda$transform$8f56fba3$1
 *
 * 在火焰图中 StreamFilter 占据大量采样 (W=23943)，
 * 这是因为它是 Source 链上 chaining 后第一个 operator，
 * 后续的 ProcessOperator 都在 StreamFilter 的 ChainingOutput 下调用。
 */
public class DataSourceFilter extends RichFilterFunction<ParseResult> {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceFilter.class);

    /** 需要匹配的数据源 ID */
    private final String targetDataSourceId;

    public DataSourceFilter(String targetDataSourceId) {
        this.targetDataSourceId = targetDataSourceId;
    }

    @Override
    public void open(Configuration parameters) throws Exception {
        super.open(parameters);
        LOG.info("DataSourceFilter opened for dataSourceId: {}", targetDataSourceId);
    }

    /**
     * 过滤逻辑 — 仅保留匹配目标数据源的数据。
     * 对应火焰图:
     *   StreamFilter.processElement
     *     → AbstractDataSourceTransformer.lambda$transform$8f56fba3$1
     */
    @Override
    public boolean filter(ParseResult value) throws Exception {
        if (targetDataSourceId == null || targetDataSourceId.isEmpty()) {
            return true; // 无过滤条件时全部通过
        }
        return targetDataSourceId.equals(value.getDataSourceId());
    }
}
