package com.example.demo.operator.canvas.api;

import com.example.demo.record.ParseResult;
import org.apache.flink.streaming.api.functions.ProcessFunction;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 画布处理函数基类 — 所有画布算子的入口。
 * 对应火焰图中:
 *   org/apache/flink/streaming/api/operators/ProcessOperator.processElement
 *     → com/meituan/rc/zeus/nearline/flink/operator/canvas/api/CanvasProcessFunction.processElement
 *       → (子类).onProcessElement
 *
 * 该类封装了画布算子的通用逻辑：
 *   - buildGraphElement: 构建图元素
 *   - setMDC / clearMDC: 设置/清除日志上下文
 *   - setUpUdfThreadInfo / clearUdfThreadInfo: 线程信息管理
 */
public abstract class CanvasProcessFunction extends ProcessFunction<ParseResult, ParseResult> {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CanvasProcessFunction.class);

    /** 算子 ID */
    protected final String operatorId;

    protected CanvasProcessFunction(String operatorId) {
        this.operatorId = operatorId;
    }

    /**
     * Flink 调用入口。
     * 对应火焰图:
     *   CanvasProcessFunction.processElement
     *     → setMDC → setUpUdfThreadInfo → onProcessElement → clearUdfThreadInfo → clearMDC
     */
    @Override
    public void processElement(ParseResult value, Context ctx, Collector<ParseResult> out) throws Exception {
        try {
            setMDC(value);
            setUpUdfThreadInfo();
            buildGraphElement(value);
            onProcessElement(value, ctx, out);
        } catch (Exception e) {
            LOG.error("CanvasProcessFunction[{}] error: {}", operatorId, e.getMessage(), e);
        } finally {
            clearUdfThreadInfo();
            clearMDC();
        }
    }

    /**
     * 子类实现的核心处理逻辑。
     */
    protected abstract void onProcessElement(ParseResult value, Context ctx, Collector<ParseResult> out) throws Exception;

    /**
     * 获取图函数 ID。
     * 对应火焰图: CanvasProcessFunction.getGraphFunctionId
     */
    public String getGraphFunctionId() {
        return operatorId;
    }

    /**
     * 构建图元素。
     * 对应火焰图: CanvasProcessFunction.buildGraphElement
     */
    protected void buildGraphElement(ParseResult value) {
        // 根据配置构建画布图元素
    }

    /**
     * 设置 MDC 日志上下文。
     * 对应火焰图: CanvasProcessFunction.setMDC
     */
    protected void setMDC(ParseResult value) {
        // 设置日志追踪信息（canvasId, dataSourceId 等）
    }

    /**
     * 清除 MDC 日志上下文。
     * 对应火焰图: CanvasProcessFunction.clearMDC
     */
    protected void clearMDC() {
        // 清除日志追踪信息
    }

    /**
     * 设置 UDF 线程信息。
     * 对应火焰图: CanvasProcessFunction.setUpUdfThreadInfo
     */
    protected void setUpUdfThreadInfo() {
        Thread.currentThread().setName("canvas-" + operatorId);
    }

    /**
     * 清除 UDF 线程信息。
     * 对应火焰图: CanvasProcessFunction.clearUdfThreadInfo
     */
    protected void clearUdfThreadInfo() {
        // 清理线程局部变量
    }
}
