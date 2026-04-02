package com.example.demo.operator.canvas;

import com.example.demo.operator.canvas.api.CanvasProcessFunction;
import com.example.demo.record.ParseResult;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 画布合流算子 — 将多个数据源合并为统一流。
 * 对应火焰图中:
 *   ProcessOperator.processElement
 *     → CanvasTwoInputFunction.processElement / CanvasProcessFunction.processElement
 *       → CanvasUnionFunction.onProcessElement
 *         → TimestampedCollector.collect → CountingOutput.collect → ...
 *
 * 此算子在 OneInputStreamTask 的处理链中出现:
 *   AbstractStreamTaskNetworkInput.emitNext
 *     → AbstractStreamTaskNetworkInput.processElement
 *       → OneInputStreamTask$StreamTaskNetworkOutput.emitRecord
 *         → ProcessOperator.processElement
 *           → CanvasUnionFunction.onProcessElement
 */
public class CanvasUnionFunction extends CanvasProcessFunction {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CanvasUnionFunction.class);

    public CanvasUnionFunction(String operatorId) {
        super(operatorId);
    }

    /**
     * 合流处理 — 直接透传数据。
     * 对应火焰图:
     *   CanvasUnionFunction.onProcessElement
     *     → Collector.collect (下游 ChainingOutput)
     */
    @Override
    protected void onProcessElement(ParseResult value, Context ctx, Collector<ParseResult> out) throws Exception {
        // 合流算子：直接透传，不做数据变换
        out.collect(value);
    }
}
