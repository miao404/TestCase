package com.example.demo.operator.parse;

import com.example.demo.record.ObjectMap;
import com.example.demo.record.ParseResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;

/**
 * 通用日志解析器 — 将原始 JSON 字符串解析为 ParseResult。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/operator/parse/CommonParse.parseValue
 */
public class CommonParse implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CommonParse.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 解析原始值为 ParseResult。
     * 对应火焰图: CommonParse.parseValue
     *   → ObjectMapper.readValue (Jackson 解析)
     *   → 字段提取与赋值
     */
    public ParseResult parseValue(String rawValue) {
        ParseResult result = new ParseResult();
        if (rawValue == null || rawValue.trim().isEmpty()) {
            return result;
        }

        try {
            JsonNode root = MAPPER.readTree(rawValue);

            // 提取基本字段
            result.setUrl(getTextValue(root, "url"));
            result.setRequestBody(getTextValue(root, "requestBody"));
            result.setResponseBody(getTextValue(root, "responseBody"));
            result.setCanvasId(getTextValue(root, "canvasId"));
            result.setDataSourceId(getTextValue(root, "dataSourceId"));

            // 提取事件时间
            if (root.has("eventTime")) {
                result.setEventTime(root.get("eventTime").asLong(System.currentTimeMillis()));
            } else {
                result.setEventTime(System.currentTimeMillis());
            }

            // 提取扩展字段到 ObjectMap
            ObjectMap fields = new ObjectMap();
            if (root.has("fields") && root.get("fields").isObject()) {
                JsonNode fieldsNode = root.get("fields");
                Iterator<Map.Entry<String, JsonNode>> it = fieldsNode.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> entry = it.next();
                    fields.put(entry.getKey(), entry.getValue().isTextual()
                            ? entry.getValue().asText()
                            : entry.getValue().toString());
                }
            }
            result.setFields(fields);

        } catch (Exception e) {
            LOG.warn("Failed to parse raw value, treating as raw requestBody: {}", e.getMessage());
            // 解析失败时把原始数据作为 requestBody
            result.setRequestBody(rawValue);
            result.setEventTime(System.currentTimeMillis());
        }

        return result;
    }

    private String getTextValue(JsonNode node, String fieldName) {
        if (node.has(fieldName) && !node.get(fieldName).isNull()) {
            return node.get(fieldName).asText();
        }
        return null;
    }
}
