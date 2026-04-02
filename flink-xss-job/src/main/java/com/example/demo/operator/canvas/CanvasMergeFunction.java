package com.example.demo.operator.canvas;

import com.example.demo.operator.canvas.api.CanvasProcessFunction;
import com.example.demo.record.ParseResult;
import com.example.demo.record.XssResult;
import com.example.demo.xss;
import org.apache.flink.util.Collector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 画布合并/路由算子 — 负责规则路由、条件分支、代码执行（XSS 检测）等。
 * 这是 work1 火焰图中最核心的算子，占据了绝大部分 CPU 采样。
 *
 * 对应火焰图中的完整调用链:
 *   ProcessOperator.processElement
 *     → CanvasProcessFunction.processElement
 *       → CanvasMergeFunction.onProcessElement
 *         → doBefore (前置处理)
 *         → doProcess (核心处理)
 *           → processIfElse (条件分支路由)
 *             → processRuleSet (规则集处理)
 *               → routeRuleSet
 *             → ProcessOperator$ContextImpl.output
 *           → processCode (代码执行 — XSS 检测入口)
 *             → xss.process ← 火焰图最大热点
 *               → xss.detectXssInRequestBody
 *                 → xss.detectXss → xss.extract → xss.canonicalizeWithCount
 *               → xss.detectXssInResponseBody
 *                 → xss.detectXss → xss.detectXssInExtractedData → xss.detectXssCore
 *               → xss.detectXssInUrl
 *           → processSplit (分裂处理)
 *           → processDrop (丢弃处理)
 *         → doAfter (后置处理)
 *           → queueSingleOutput
 */
public class CanvasMergeFunction extends CanvasProcessFunction {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CanvasMergeFunction.class);

    /** XSS 检测阈值 */
    private final int xssThreshold;

    public CanvasMergeFunction(String operatorId, int xssThreshold) {
        super(operatorId);
        this.xssThreshold = xssThreshold;
    }

    /**
     * 核心处理入口。
     * 对应火焰图:
     *   CanvasMergeFunction.onProcessElement → doBefore → doProcess → doAfter
     */
    @Override
    protected void onProcessElement(ParseResult value, Context ctx, Collector<ParseResult> out) throws Exception {
        MsgHolder holder = new MsgHolder(value);

        doBefore(holder);
        doProcess(holder, ctx, out);
        doAfter(holder, out);
    }

    /**
     * 前置处理。
     * 对应火焰图: CanvasMergeFunction.doBefore
     */
    private void doBefore(MsgHolder holder) {
        // 前置校验、指标上报等
    }

    /**
     * 核心处理 — 根据算子类型分发到不同处理逻辑。
     * 对应火焰图:
     *   CanvasMergeFunction.doProcess
     *     → processIfElse / processCode / processSplit / processDrop
     */
    private void doProcess(MsgHolder holder, Context ctx, Collector<ParseResult> out) throws Exception {
        ParseResult input = holder.getInput();

        // 条件分支路由
        processIfElse(holder, ctx, out);

        // 代码执行 — XSS 检测（火焰图最大热点）
        processCode(holder);

        // 分裂处理
        processSplit(holder);

        // 丢弃处理
        processDrop(holder);
    }

    /**
     * 条件分支路由。
     * 对应火焰图:
     *   CanvasMergeFunction.processIfElse
     *     → processRuleSet → routeRuleSet
     *     → ProcessOperator$ContextImpl.output
     */
    private void processIfElse(MsgHolder holder, Context ctx, Collector<ParseResult> out) {
        ParseResult input = holder.getInput();
        // 根据规则条件决定数据路由方向
        processRuleSet(input);
    }

    /**
     * 规则集处理。
     * 对应火焰图:
     *   CanvasMergeFunction.processRuleSet
     *     → routeRuleSet
     *     → lambda$processRuleSet$0 / $1 / $5
     */
    private void processRuleSet(ParseResult input) {
        routeRuleSet(input);
    }

    /**
     * 规则路由。
     * 对应火焰图: CanvasMergeFunction.routeRuleSet
     */
    private void routeRuleSet(ParseResult input) {
        // 根据规则引擎结果路由数据
    }

    /**
     * 代码执行 — XSS 检测（火焰图中的最大热点）。
     * 对应火焰图:
     *   CanvasMergeFunction.processCode
     *     → xss.process (W=16464, 占总采样的 31.4%)
     *       → xss.detectXssInRequestBody (W=1632)
     *         → xss.detectXss → xss.extract → xss.canonicalizeWithCount
     *       → xss.detectXssInResponseBody (W=14473)
     *         → xss.detectXss → xss.detectXssInExtractedData → xss.detectXssCore
     *       → xss.detectXssInUrl
     *       → xss.filterXssRisk
     */
    private void processCode(MsgHolder holder) {
        ParseResult input = holder.getInput();
        XssResult xssResult = xss.process(input, xssThreshold);
        holder.setXssResult(xssResult);

        // 将 XSS 检测结果写回 fields
        if (xssResult != null) {
            input.getFields().put("__xss_detected", String.valueOf(xssResult.isXssDetected()));
            input.getFields().put("__xss_max_score", String.valueOf(xssResult.getMaxScore()));
        }
    }

    /**
     * 分裂处理。
     * 对应火焰图: CanvasMergeFunction.processSplit
     */
    private void processSplit(MsgHolder holder) {
        // 数据分裂逻辑
    }

    /**
     * 丢弃处理。
     * 对应火焰图: CanvasMergeFunction.processDrop
     */
    private void processDrop(MsgHolder holder) {
        // 根据条件丢弃数据
    }

    /**
     * 后置处理 — 输出结果。
     * 对应火焰图:
     *   CanvasMergeFunction.doAfter
     *     → queueSingleOutput
     */
    private void doAfter(MsgHolder holder, Collector<ParseResult> out) {
        queueSingleOutput(holder, out);
    }

    /**
     * 排队单条输出。
     * 对应火焰图: CanvasMergeFunction.queueSingleOutput
     */
    private void queueSingleOutput(MsgHolder holder, Collector<ParseResult> out) {
        for (ParseResult msg : holder.getOutMessages()) {
            out.collect(msg);
        }
        // 如果没有显式输出，则输出原始数据
        if (holder.getOutMessages().isEmpty()) {
            out.collect(holder.getInput());
        }
    }

    // =========================================================================
    // 内部类: MsgHolder — 消息持有器
    // =========================================================================

    /**
     * 消息持有器 — 在算子处理过程中承载输入/输出消息。
     * 对应火焰图:
     *   CanvasMergeFunction$MsgHolder.<init>
     *   CanvasMergeFunction$MsgHolder.addOutMsg
     *   CanvasMergeFunction$MsgHolder.removeOutMsg
     */
    static class MsgHolder {
        private final ParseResult input;
        private final List<ParseResult> outMessages;
        private XssResult xssResult;

        MsgHolder(ParseResult input) {
            this.input = input;
            this.outMessages = new ArrayList<>();
        }

        ParseResult getInput() {
            return input;
        }

        List<ParseResult> getOutMessages() {
            return outMessages;
        }

        void addOutMsg(ParseResult msg) {
            outMessages.add(msg);
        }

        void removeOutMsg(ParseResult msg) {
            outMessages.remove(msg);
        }

        XssResult getXssResult() {
            return xssResult;
        }

        void setXssResult(XssResult xssResult) {
            this.xssResult = xssResult;
        }
    }
}
