package com.example.demo.operator.canvas;

import com.example.demo.operator.canvas.api.CanvasProcessFunction;
import com.example.demo.record.ObjectMap;
import com.example.demo.record.ParseResult;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * 画布数据源算子 — 负责数据源的初始处理和字段过滤。
 * 对应火焰图中:
 *   ProcessOperator.processElement
 *     → CanvasProcessFunction.processElement
 *       → CanvasDataSourceFunction.onProcessElement
 *         → CanvasDataSourceFunction.handleDefaultSource
 *           → ObjectMap.filterFieldAndBuildObjectMap
 *           → CanvasLogHandler.appendRequestBasicInfo
 *             → RequestUtil.genRequestId
 *         → TimestampedCollector.collect → CountingOutput.collect → ChainingOutput → ...
 */
public class CanvasDataSourceFunction extends CanvasProcessFunction {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CanvasDataSourceFunction.class);

    /** 需要保留的字段集合 */
    private final Set<String> retainFields;

    public CanvasDataSourceFunction(String operatorId, Set<String> retainFields) {
        super(operatorId);
        this.retainFields = retainFields;
    }

    /**
     * 核心处理逻辑 — 处理默认数据源。
     * 对应火焰图:
     *   CanvasDataSourceFunction.onProcessElement
     *     → handleDefaultSource
     */
    @Override
    protected void onProcessElement(ParseResult value, Context ctx, Collector<ParseResult> out) throws Exception {
        handleDefaultSource(value, ctx, out);
    }

    /**
     * 处理默认数据源 — 字段过滤、日志记录、输出。
     * 对应火焰图:
     *   CanvasDataSourceFunction.handleDefaultSource
     *     → ObjectMap.filterFieldAndBuildObjectMap (字段过滤)
     *     → CanvasLogHandler.appendRequestBasicInfo (日志)
     *       → RequestUtil.genRequestId (生成请求ID)
     *     → CanvasLogHandler.appendKafkaSourceOperatorLog
     */
    private void handleDefaultSource(ParseResult value, Context ctx, Collector<ParseResult> out) {
        // 字段过滤
        if (retainFields != null && !retainFields.isEmpty()) {
            ObjectMap filtered = ObjectMap.filterFieldAndBuildObjectMap(value.getFields(), retainFields);
            value.setFields(filtered);
        }

        // 追加请求基本信息日志
        appendRequestBasicInfo(value);

        // 输出
        out.collect(value);
    }

    /**
     * 追加请求基本信息。
     * 对应火焰图:
     *   CanvasLogHandler.appendRequestBasicInfo
     *     → RequestUtil.genRequestId
     */
    private void appendRequestBasicInfo(ParseResult value) {
        String requestId = genRequestId();
        value.getFields().put("__requestId", requestId);
    }

    /**
     * 生成请求 ID。
     * 对应火焰图: RequestUtil.genRequestId
     */
    private String genRequestId() {
        return "req-" + System.nanoTime();
    }
}
