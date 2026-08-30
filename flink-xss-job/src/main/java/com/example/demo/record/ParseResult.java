package com.example.demo.record;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * 日志解析结果，承载从 Kafka 消费后经过 MapLogParse 解析出的结构化数据。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/record/ParseResult
 */
public class ParseResult implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 请求 URL */
    private String url;

    /** 请求体 */
    private String requestBody;

    /** 响应体 */
    private String responseBody;

    /** 事件时间戳 */
    private long eventTime;

    /** 画布 ID */
    private String canvasId;

    /** 数据源 ID */
    private String dataSourceId;

    /** 扩展字段 */
    private ObjectMap fields;

    /** 规则隔离映射 */
    private Map<String, Object> ruleIsolateMap;

    public ParseResult() {
        this.fields = new ObjectMap();
        this.ruleIsolateMap = new HashMap<>();
    }

    public ParseResult copy() {
        ParseResult result = new ParseResult();
        result.url = this.url;
        result.requestBody = this.requestBody;
        result.responseBody = this.responseBody;
        result.eventTime = this.eventTime;
        result.canvasId = this.canvasId;
        result.dataSourceId = this.dataSourceId;
        result.fields = new ObjectMap(this.fields);
        result.ruleIsolateMap = deepObjectCopyMap(this.ruleIsolateMap);
        return result;
    }

    public ParseResult deepCopyObj() {
        return copy();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> deepObjectCopyMap(Map<String, Object> source) {
        if (source == null) {
            return new HashMap<>();
        }
        Map<String, Object> copy = new HashMap<>(source.size());
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                copy.put(entry.getKey(), deepObjectCopyMap((Map<String, Object>) value));
            } else {
                copy.put(entry.getKey(), value);
            }
        }
        return copy;
    }

    public void filterTmpVariables() {
        if (fields != null) {
            fields.filterVariables();
        }
    }

    // =========================================================================
    // Getters / Setters
    // =========================================================================

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public long getEventTime() {
        return eventTime;
    }

    public void setEventTime(long eventTime) {
        this.eventTime = eventTime;
    }

    public String getCanvasId() {
        return canvasId;
    }

    public void setCanvasId(String canvasId) {
        this.canvasId = canvasId;
    }

    public String getDataSourceId() {
        return dataSourceId;
    }

    public void setDataSourceId(String dataSourceId) {
        this.dataSourceId = dataSourceId;
    }

    public ObjectMap getFields() {
        return fields;
    }

    public void setFields(ObjectMap fields) {
        this.fields = fields;
    }

    public Map<String, Object> getRuleIsolateMap() {
        return ruleIsolateMap;
    }

    public void setRuleIsolateMap(Map<String, Object> ruleIsolateMap) {
        this.ruleIsolateMap = ruleIsolateMap;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParseResult that = (ParseResult) o;
        if (eventTime != that.eventTime) return false;
        if (url != null ? !url.equals(that.url) : that.url != null) return false;
        if (requestBody != null ? !requestBody.equals(that.requestBody) : that.requestBody != null) return false;
        if (responseBody != null ? !responseBody.equals(that.responseBody) : that.responseBody != null) return false;
        return canvasId != null ? canvasId.equals(that.canvasId) : that.canvasId == null;
    }

    @Override
    public int hashCode() {
        int result = url != null ? url.hashCode() : 0;
        result = 31 * result + (requestBody != null ? requestBody.hashCode() : 0);
        result = 31 * result + (int) (eventTime ^ (eventTime >>> 32));
        result = 31 * result + (canvasId != null ? canvasId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ParseResult{" +
                "url='" + url + '\'' +
                ", canvasId='" + canvasId + '\'' +
                ", dataSourceId='" + dataSourceId + '\'' +
                ", eventTime=" + eventTime +
                ", fieldsSize=" + (fields != null ? fields.size() : 0) +
                '}';
    }
}
