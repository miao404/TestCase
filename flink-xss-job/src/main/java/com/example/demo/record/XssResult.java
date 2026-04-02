package com.example.demo.record;

import java.io.Serializable;
import java.util.Map;

/**
 * XSS 检测结果封装。
 * 承载 xss.process 的输出结果，包括 URL / 请求体 / 响应体 三部分的检测结论。
 */
public class XssResult implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 原始解析结果 */
    private ParseResult parseResult;

    /** URL XSS 检测结果 */
    private Map<String, Object> urlResult;

    /** 请求体 XSS 检测结果 */
    private Map<String, Object> requestBodyResult;

    /** 响应体 XSS 检测结果 */
    private Map<String, Object> responseBodyResult;

    /** 是否检测到 XSS */
    private boolean xssDetected;

    /** 最高风险分 */
    private int maxScore;

    public XssResult() {
    }

    public ParseResult getParseResult() {
        return parseResult;
    }

    public void setParseResult(ParseResult parseResult) {
        this.parseResult = parseResult;
    }

    public Map<String, Object> getUrlResult() {
        return urlResult;
    }

    public void setUrlResult(Map<String, Object> urlResult) {
        this.urlResult = urlResult;
    }

    public Map<String, Object> getRequestBodyResult() {
        return requestBodyResult;
    }

    public void setRequestBodyResult(Map<String, Object> requestBodyResult) {
        this.requestBodyResult = requestBodyResult;
    }

    public Map<String, Object> getResponseBodyResult() {
        return responseBodyResult;
    }

    public void setResponseBodyResult(Map<String, Object> responseBodyResult) {
        this.responseBodyResult = responseBodyResult;
    }

    public boolean isXssDetected() {
        return xssDetected;
    }

    public void setXssDetected(boolean xssDetected) {
        this.xssDetected = xssDetected;
    }

    public int getMaxScore() {
        return maxScore;
    }

    public void setMaxScore(int maxScore) {
        this.maxScore = maxScore;
    }

    @Override
    public String toString() {
        return "XssResult{" +
                "xssDetected=" + xssDetected +
                ", maxScore=" + maxScore +
                ", canvasId=" + (parseResult != null ? parseResult.getCanvasId() : "null") +
                '}';
    }
}
