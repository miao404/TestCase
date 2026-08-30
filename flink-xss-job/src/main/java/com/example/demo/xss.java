package com.example.demo;

import com.example.demo.record.ParseResult;
import com.example.demo.record.XssResult;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 • 通用XSS检测器 - 增强版

 • 特性：

 • 1. 静态正则预编译，高性能

 • 2. 上下文感知的误报抑制

 • 3. 恶意组合特征检测

 • 4. 现代前端框架注入检测


 • 5. 高级混淆与绕过对抗

 • 6. iframe + javascript伪协议检测

 • 7. 动态脚本注入检测

 */
public class xss {

    // Jackson 工厂 (线程安全，需单例)
    private static final JsonFactory jsonFactory = new JsonFactory();

    // =========================================================================
    // 配置常量
    // =========================================================================
    private static final int MIN_LEN = 5;      // 最小分析长度
    private static final int MAX_LEN = 50000;  // 最大分析长度
    private static final int MAX_JSON_DEPTH = 10; // JSON 递归最大深度 (防止栈溢出)

    // 日志采样配置
    private static final int PARSE_FAILURE_SAMPLE_RATE = 100; // 每100次失败记录1次（1%采样率）
    private static volatile int jsonParseFailureCount = 0;    // JSON解析失败计数
    private static volatile int formParseFailureCount = 0;    // FormData解析失败计数

    // =========================================================================
    // 正则预编译（性能优化：所有正则都预编译并添加优化标志）
    // =========================================================================

    // HTML实体解码正则
    static final Pattern HEX_ENTITY = Pattern.compile("&#x([0-9a-fA-F]+);", Pattern.CASE_INSENSITIVE);
    static final Pattern DEC_ENTITY = Pattern.compile("&#([0-9]+);");
    private static final Pattern UNICODE_PATTERN = Pattern.compile("\\\\u([0-9a-fA-F]{4})", Pattern.CASE_INSENSITIVE);

    // 截断JSON提取正则
    private static final Pattern LAST_INCOMPLETE_STRING = Pattern.compile("\"([^\"]+)$");

    // XSS核心符号检测正则（必须包含这些符号才可能是XSS）
    // 包括: < > ( ) = [ ] ' " { } 这些是XSS攻击中最常用的符号
    // 覆盖率：95%以上的XSS攻击
    private static final Pattern XSS_CORE_PATTERN = Pattern.compile(
            "[<>()=\\[\\]'\"{}]"
    );

    // 纯字母数字检测正则（预编译以提高性能）
    private static final Pattern ALPHANUMERIC_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\.]+$");

    // 纯中文检测正则（预编译以提高性能）
    private static final Pattern CHINESE_PATTERN = Pattern.compile("^[\\u4E00-\\u9FFF\\s]+$");

    // HTML标签提取正则（预编译以提高性能）
    // 匹配 <tagname 或 </tagname，标签名后面可能跟空格、>、/或其他属性
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("</?([a-z][a-z0-9]*)[\\s>/]", Pattern.CASE_INSENSITIVE);
    private static final Pattern IMG_TAG_PATTERN = Pattern.compile("<img[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern A_TAG_PATTERN = Pattern.compile("<a[^>]*>", Pattern.CASE_INSENSITIVE);

    // HTML标签移除正则（预编译以提高性能）
    private static final Pattern HTML_TAG_REMOVE_PATTERN = Pattern.compile("<[^>]+>");

    // 纯文本内容检测正则（预编译以提高性能）
    // 允许：字母、数字、空白、中文、基本标点、URL字符（/、:、&、%、#、@）
    // 允许：中文标点（、。，；：！？""''…·）和中文括号（（）【】）
    // 不允许：英文括号 ( ) [ ] { }、尖括号 < >、等号 =（这些是XSS攻击的关键字符）
    private static final Pattern SAFE_TEXT_PATTERN = Pattern.compile("^[\\s\\p{L}\\p{N},.;:!?\\-—、。，；：！？\"“‘'…·/&%#@（）【】《》「」『』]+$");

    // HTML注释移除正则（预编译以提高性能）
    private static final Pattern HTML_COMMENT_PATTERN = Pattern.compile("<!--.*?-->", Pattern.DOTALL);

// 空白字符绕过检测正则（预编译以提高性能）
// 匹配 \t \n \r \f \v 等转义序列
//    private static final Pattern WHITESPACE_BYPASS_PATTERN = Pattern.compile("\\\\[tnrfv]");

    // 空白字符移除正则（预编译以提高性能）
// 用于 repairMissingQuote 函数中移除所有空白字符
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

// =========================================================================
// Layer 1: 结构解析层
    // =========================================================================

    /**
     ◦ 主入口

     ◦ @param rawData 原始流量数据

     ◦ @return List<Map<String, Object>> 包含 normalized, decodeCount, type

     */
    public static List<Map<String, Object>> extract(String rawData) {
        List<Map<String, Object>> results = new ArrayList<>();

        if (rawData == null || rawData.length() < MIN_LEN) {
            return results;
        }

        // 【快速过滤】跳过 WebKit Form Boundary（multipart/form-data 的边界标记）
        // 这些是表单上传的边界标记，不需要进行 XSS 检测

        // ===== 步骤1: 先对整体数据进行归一化和解码 =====
        Map<String, Object> canonicalResult = canonicalizeWithCount(rawData);
        String normalizedData = (String) canonicalResult.get("normalized");
        int initialDecodeCount = (Integer) canonicalResult.get("decodeCount");

        Set<String> fragments = new HashSet<>();
        String trimmed = normalizedData.trim();
        String detectedType = "RAW";
        boolean extractionSuccess = false;

        // ===== 步骤2: 对归一化后的数据尝试 JSON 解析 =====
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                // 【优化】先尝试整体 JSON 解析（更快）
                boolean wholeParseSuccess = parseJsonWhole(normalizedData, fragments);

                if (wholeParseSuccess && !fragments.isEmpty()) {
                    extractionSuccess = true;
                    detectedType = "JSON";
                } else {
                    // 整体解析失败，降级到流式解析
                    fragments.clear();
                    parseJsonStream(normalizedData, fragments, 0);
                    if (!fragments.isEmpty()) {
                        extractionSuccess = true;
                        detectedType = "JSON";
                    }
                }
            } catch (Exception e) {
                // JSON 解析彻底崩溃，准备降级
                // 抽样记录日志
                logJsonParseFailure(normalizedData, e);
            }
        }
        // 3. 尝试 Form Data 解析 (如果 JSON 没成功)
        else if (normalizedData.contains("=") && normalizedData.contains("&")) {
            try {
                parseFormDataStream(normalizedData, fragments);
                if (!fragments.isEmpty()) {
                    extractionSuccess = true;
                    detectedType = "FORM";
                }
            } catch (Exception e) {
                // FormData 解析失败，抽样记录日志
                logFormParseFailure(normalizedData, e);
            }
        }

        // 4. 兜底策略：如果解析失败或未提取到任何内容，使用归一化后的数据
        if (!extractionSuccess || fragments.isEmpty()) {
            fragments.add(normalizedData);
            detectedType = "RAW";
        }

        // ===== 步骤3: 对每个 fragment 进行进一步的归一化和解码 =====
        for (String fragment : fragments) {
            // 长度过滤
            if (fragment.length() < MIN_LEN || fragment.length() > MAX_LEN) {
                continue;
            }

            // 再次归一化并获取解码次数
            Map<String, Object> fragmentCanonicalResult = canonicalizeWithCount(fragment);
            int fragmentDecodeCount = (Integer) fragmentCanonicalResult.get("decodeCount");

            // 总解码次数 = 初始解码次数 + fragment解码次数 - 1（避免重复计数）
            int totalDecodeCount = initialDecodeCount + fragmentDecodeCount - 1;

            Map<String, Object> item = new HashMap<>();
            item.put("normalized", fragmentCanonicalResult.get("normalized"));
            item.put("decodeCount", totalDecodeCount);
            item.put("type", detectedType);

            results.add(item);
        }

        return results;
    }

    /**
     ◦ JSON 整体解析（优先使用，性能更好）

     ◦ 尝试将整个 JSON 字符串一次性解析为 Map 或 List

     *
     ◦ @param content JSON 字符串

     ◦ @param collector 收集器

     ◦ @return true 表示解析成功，false 表示需要降级到流式解析

     */
    private static boolean parseJsonWhole(String content, Set<String> collector) {
        if (content == null || content.trim().isEmpty()) {
            return false;
        }

        try {
            // 使用 Jackson 的 ObjectMapper 进行整体解析
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();

            // 尝试解析为 Map 或 List
            Object parsed = null;
            String trimmed = content.trim();
            String contentToparse = trimmed;

            if (trimmed.startsWith("{")) {
                // 【优化】检查是否以 } 结尾，如果不是则尝试修复
                if (!trimmed.endsWith("}")) {
                    contentToparse = repairJsonClosing(trimmed, "{", "}");
                }
                // 解析为 Map
                parsed = mapper.readValue(contentToparse, Map.class);
            } else if (trimmed.startsWith("[")) {
                // 【优化】检查是否以 ] 结尾，如果不是则尝试修复
                if (!trimmed.endsWith("]")) {
                    contentToparse = repairJsonClosing(trimmed, "[", "]");
                }
                // 解析为 List
                parsed = mapper.readValue(contentToparse, List.class);
            } else {
                return false;
            }

            // 递归提取所有字符串值
            extractJsonValues(parsed, collector, 0);

            return true;
        } catch (Exception e) {
            // 整体解析失败，返回 false 以降级到流式解析
            return false;
        }
    }

    /**
     ◦ 修复不完整的 JSON 字符串

     ◦ 考虑 { [ 混用的情况，使用栈来追踪括号的匹配

     ◦ 同时处理最后一个字段值缺少 " 的情况

     *
     ◦ @param content JSON 字符串

     ◦ @param openBracket 开括号（{ 或 [）

     ◦ @param closeBracket 闭括号（} 或 ]）

     ◦ @return 修复后的 JSON 字符串

     */
    private static String repairJsonClosing(String content, String openBracket, String closeBracket) {
        if (content == null || content.isEmpty()) {
            return content;
        }

        // 【第一步】检查并修复最后一个字段值缺少 " 的情况
        String repairedContent = repairMissingQuote(content);

        // 【第二步】使用栈来追踪括号的匹配关系
        Stack<Character> bracketStack = new Stack<>();
        boolean inString = false;
        char stringChar = '\0';

        for (int i = 0; i < repairedContent.length(); i++) {
            char c = repairedContent.charAt(i);

            // 处理字符串内容（避免计算字符串中的括号）
            if ((c == '"' || c == '\'' || c == '`') && (i == 0 || repairedContent.charAt(i - 1) != '\\')) {
                if (!inString) {
                    inString = true;
                    stringChar = c;
                } else if (c == stringChar) {
                    inString = false;
                }
                continue;
            }

            // 如果在字符串内，跳过
            if (inString) {
                continue;
            }

            // 处理开括号
            if (c == '{' || c == '[') {
                bracketStack.push(c);
            }
            // 处理闭括号
            else if (c == '}' || c == ']') {
                if (!bracketStack.isEmpty()) {
                    char top = bracketStack.peek();
                    // 检查括号是否匹配
                    if ((c == '}' && top == '{') || (c == ']' && top == '[')) {
                        bracketStack.pop();
                    }
                }
            }
        }

        // 【第三步】根据栈中剩余的括号生成修复字符串
        StringBuilder sb = new StringBuilder(repairedContent);
        while (!bracketStack.isEmpty()) {
            char openChar = bracketStack.pop();
            if (openChar == '{') {
                sb.append('}');
            } else if (openChar == '[') {
                sb.append(']');
            }
        }

        return sb.toString();
    }

    /**
     ◦ 修复最后一个字段值缺少结尾引号的情况

     ◦ 支持多种不完整场景：

     ◦ - {"asf":"asf → {"asf":"asf"

     ◦ - {"asd": → {"asd":""

     ◦ - {"asd → {"asd":""

     ◦ - {"asd":"asf","waasg" → {"asd":"asf","waasg":""

     ◦ - {"asd":"asf", → {"asd":"asf"

     *
     ◦ 核心逻辑：

     ◦ 1. 如果以逗号结尾，直接去掉逗号

     ◦ 2. 如果以冒号结尾，补上空字符串 ""

     ◦ 3. 统计引号数量，如果是奇数（未配对），先补上引号

     ◦ 4. 检查最后一个完整字段后是否还有未完成的键，补上 :""

     ◦ 5. 正确处理转义字符，避免将 \" 误判为引号

     *
     ◦ 注意：此函数在 repairJsonClosing 中被调用，会先修复引号，再补全括号

     *
     ◦ @param content 不完整的 JSON 字符串（通常不包含闭合括号）

     ◦ @return 修复后的 JSON 字符串

     */
    private static String repairMissingQuote(String content) {
        if (content == null || content.isEmpty()) {
            return content;
        }

        String trimmed = content.trim();
        int len = trimmed.length();

        if (len == 0) {
            return content;
        }

        // 特殊情况：如果以冒号结尾，说明值缺失，补上空字符串 ""
        // 例如：{"asd": → {"asd":""
        if (trimmed.endsWith(":")) {
            return trimmed + "\"\"";
        }

        // 一次遍历：统计引号数量、记录逗号和冒号位置
        int quoteCount = 0;
        int lastCommaPos = -1;  // 最后一个逗号的位置
        int lastColonPos = -1;  // 最后一个冒号的位置
        boolean inString = false; // 标记是否在字符串内部

        for (int i = 0; i < len; i++) {
            char c = trimmed.charAt(i);

            // 处理转义：需要正确识别转义序列
            // 关键：统计前面有多少个连续的反斜杠
            if (c == '\\') {
                int backslashCount = 0;
                int j = i;
                // 向后统计连续的反斜杠数量
                while (j < len && trimmed.charAt(j) == '\\') {
                    backslashCount++;
                    j++;
                }

                // 如果反斜杠后面是引号
                if (j < len && trimmed.charAt(j) == '"') {
                    // 偶数个反斜杠：反斜杠互相转义，引号是真实引号
                    // 奇数个反斜杠：最后一个反斜杠转义引号，引号不是真实引号
                    if (backslashCount % 2 == 0) {
                        // 偶数个反斜杠，引号是真实的
                        i = j - 1; // 跳过所有反斜杠，下一轮处理引号
                    } else {
                        // 奇数个反斜杠，引号被转义
                        i = j; // 跳过所有反斜杠和被转义的引号
                    }
                    continue;
                } else {
                    // 反斜杠后面不是引号，跳过所有反斜杠
                    i = j - 1;
                    continue;
                }
            }

            // 统计双引号（只处理双引号，因为 JSON 标准只支持双引号）
            if (c == '"') {
                quoteCount++;
                inString = !inString; // 切换字符串状态
            }

            // 记录最后一个逗号的位置（只记录字符串外的逗号）
            if (c == ',' && !inString) {
                lastCommaPos = i;
            }

            // 记录最后一个冒号的位置（只记录字符串外的冒号）
            if (c == ':' && !inString) {
                lastColonPos = i;
            }
        }

        // 检查最后一个逗号后是否只有无效内容（空或单引号）
        // 例如：{"asd":"asf"," → {"asd":"asf"  或  {"asd":"asf",  " → {"asd":"asf"
        if (lastCommaPos != -1) {
            String afterComma = trimmed.substring(lastCommaPos + 1).trim();
            // 如果逗号后只有引号、空字符串或空白，去掉逗号及之后的内容
            if (afterComma.isEmpty() || afterComma.equals("\"")) {
                return trimmed.substring(0, lastCommaPos);
            }
        }

        // 如果引号数量是奇数，说明有未闭合的引号，在末尾补上
        // 例如：{"asd → {"asd"  或  {"asf":"asf → {"asf":"asf"
        if (quoteCount % 2 == 1) {
            // 避免重复添加引号
            if (!trimmed.endsWith("\"")) {
                trimmed = trimmed + "\"";
                quoteCount++; // 更新引号数量
            }
        }

        // 现在引号已经配对了，检查是否需要补充冒号和值
        if (quoteCount > 0 && quoteCount % 2 == 0) {
            // 情况A：最后一个逗号在最后一个冒号之后
            // 说明有新的键开始了，需要检查是否需要补值
            if (lastCommaPos > lastColonPos) {
                // 获取最后一个逗号后的内容（去除所有空白字符）
                String afterComma = trimmed.substring(lastCommaPos + 1);
                String afterCommaNoSpace = WHITESPACE_PATTERN.matcher(afterComma).replaceAll("");

                // 检查逗号后是否有冒号
                int colonIdx = afterCommaNoSpace.indexOf(':');

                if (colonIdx == -1) {
                    // 没有冒号，说明只有键，补上 :""
                    return trimmed + ":\"\"";
                } else {
                    // 有冒号，检查冒号后是否有值
                    String valueAfterColon = afterCommaNoSpace.substring(colonIdx + 1);

                    if (valueAfterColon.isEmpty()) {
                        // 冒号后为空，补上 ""
                        return trimmed + "\"\"";
                    } else if (valueAfterColon.startsWith("\"")) {
                        // 冒号后有引号，说明是字符串值，检查引号是否配对
                        int quoteCountInValue = 0;
                        for (int i = 0; i < valueAfterColon.length(); i++) {
                            char c = valueAfterColon.charAt(i);
                            if (c == '\\' && i + 1 < valueAfterColon.length()) {
                                i++; // 跳过转义字符
                                continue;
                            }
                            if (c == '"') {
                                quoteCountInValue++;
                            }
                        }

                        // 如果引号数量是奇数，说明字符串未闭合，补上引号
                        if (quoteCountInValue % 2 == 1) {
                            return trimmed + "\"";
                        }
                        // 引号已配对，不需要补充
                    } else {
                        // 冒号后有非引号字符，检查是否是对象或数组
                        if (valueAfterColon.startsWith("{") || valueAfterColon.startsWith("[")) {
                            // 是对象或数组，递归调用本函数进行修复
                            String fixedValue = repairMissingQuote(valueAfterColon);
                            // 替换原来的值
                            int colonPosInOriginal = lastCommaPos + 1 + afterComma.indexOf(':');
                            return trimmed.substring(0, colonPosInOriginal + 1) + fixedValue;
                        } else {
                            // 是 null/true/false/数字等字面量，替换为 ""
                            // 找到冒号的位置，删除冒号后的内容，补上 ""
                            return trimmed.substring(0, lastCommaPos + 1 + afterComma.indexOf(':') + 1) + "\"\"";
                        }
                    }
                }
            }
            // 情况B：没有冒号，说明只有键没有值
            else if (lastColonPos == -1) {
                return trimmed + ":\"\"";
            }
            // 情况C：有冒号但没有逗号，或者最后一个冒号在最后一个逗号之后
            else {
                // 获取最后一个冒号后的内容（去除所有空白字符）
                String afterColon = trimmed.substring(lastColonPos + 1);
                String afterColonNoSpace = WHITESPACE_PATTERN.matcher(afterColon).replaceAll("");

                if (afterColonNoSpace.isEmpty()) {
                    // 冒号后为空，补上 ""
                    return trimmed + "\"\"";
                } else if (afterColonNoSpace.startsWith("\"")) {
                    // 冒号后有引号，说明是字符串值，检查引号是否配对
                    int quoteCountAfterColon = 0;
                    for (int i = 0; i < afterColonNoSpace.length(); i++) {
                        char c = afterColonNoSpace.charAt(i);
                        if (c == '\\' && i + 1 < afterColonNoSpace.length()) {
                            i++; // 跳过转义字符
                            continue;
                        }
                        if (c == '"') {
                            quoteCountAfterColon++;
                        }
                    }

                    // 如果引号数量是奇数，说明字符串未闭合，补上引号
                    if (quoteCountAfterColon % 2 == 1) {
                        return trimmed + "\"";
                    }
                    // 引号已配对，不需要补充
                } else {
                    // 冒号后有非引号字符，检查是否是对象或数组
                    if (afterColonNoSpace.startsWith("{") || afterColonNoSpace.startsWith("[")) {
                        // 是对象或数组，递归调用本函数进行修复
                        String fixedValue = repairMissingQuote(afterColonNoSpace);
                        // 替换原来的值
                        return trimmed.substring(0, lastColonPos + 1) + fixedValue;
                    } else {
                        // 是 null/true/false/数字等字面量，替换为 ""
                        // 删除冒号后的内容，补上 ""
                        return trimmed.substring(0, lastColonPos + 1) + "\"\"";
                    }
                }
            }
        }

        return trimmed;
    }

    /**
     ◦ 检查字符串是否为数字

     *
     ◦ @param str 字符串

     ◦ @return true 表示是数字，false 表示不是

     */
    private static boolean isNumeric(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     ◦ 从解析后的 JSON 对象中递归提取所有字符串值

     *
     ◦ @param obj 解析后的对象（Map, List, String 等）

     ◦ @param collector 收集器

     ◦ @param depth 递归深度

     */
    private static void extractJsonValues(Object obj, Set<String> collector, int depth) {
        if (depth > MAX_JSON_DEPTH) {
            return; // 防止死循环
        }

        if (obj == null) {
            return;
        }

        if (obj instanceof String) {
            // 字符串值
            String value = (String) obj;

            // 【优先检查】是否是 JSON 格式字符串，如果是则递归解析（不受长度限制）
            String trimmedValue = value.trim();
            if ((trimmedValue.startsWith("{") ) ||
                    (trimmedValue.startsWith("["))) {
                // 这是一个 JSON 字符串，优先进行递归解析
                boolean nestedParseSuccess = parseJsonWhole(value, collector);

                if (!nestedParseSuccess) {
                    // 整体解析失败，尝试流式解析
                    try {
                        parseJsonStream(value, collector, depth + 1);
                    } catch (Exception e) {
                        // 流式解析也失败，才添加原始字符串
                        if (value.length() >= MIN_LEN && value.length() <= MAX_LEN) {
                            collector.add(value);
                        }
                    }
                }
                // 【重要】如果 JSON 解析成功，不添加原始的 JSON 字符串本身
                // 只保留解析出来的内容
            } else {
                // 不是 JSON 格式，按照长度限制添加
                if (value.length() >= MIN_LEN && value.length() <= MAX_LEN) {
                    collector.add(value);
                }
            }
        } else if (obj instanceof Map) {
            // Map 对象
            Map<?, ?> map = (Map<?, ?>) obj;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                // 提取 key
                if (entry.getKey() instanceof String) {
                    String key = (String) entry.getKey();
                    if (key.length() >= MIN_LEN && key.length() <= MAX_LEN) {
                        collector.add(key);
                    }
                }

                // 递归提取 value
                extractJsonValues(entry.getValue(), collector, depth + 1);
            }
        } else if (obj instanceof List) {
            // List 对象
            List<?> list = (List<?>) obj;
            for (Object item : list) {
                extractJsonValues(item, collector, depth + 1);
            }
        }
        // 【优化】忽略数字和布尔值，它们不重要
        // 不再处理 Number 和 Boolean 类型
    }

    /**
     ◦ JSON 流式解析 (支持递归和截断，增强版)

     ◦ 增强特性：

     ◦ 1. 提取JSON的key（字段名）

     ◦ 2. 提取JSON的value（字段值）

     ◦ 3. 递归解析嵌套JSON

     ◦ 4. 自动修复截断的JSON

     ◦ 5. 多种容错机制

     */
    private static void parseJsonStream(String content, Set<String> collector, int depth) {
        if (depth > MAX_JSON_DEPTH) return; // 防止死循环
        if (content == null || content.trim().isEmpty()) return;

        JsonParser parser = null;
        try {
            parser = jsonFactory.createParser(content);
            String currentFieldName = null;

            JsonToken token;
            while ((token = parser.nextToken()) != null) {

                // 提取字段名（key）
                if (token == JsonToken.FIELD_NAME) {
                    currentFieldName = parser.getCurrentName();

                    if (currentFieldName != null && currentFieldName.length() >= MIN_LEN) {
                        collector.add(currentFieldName);
                    }
                }

                // 提取字符串值（value）
                else if (token == JsonToken.VALUE_STRING) {
                    String value = parser.getText();

                    if (value != null && value.length() >= MIN_LEN) {

                        String vTrim = value.trim();
                        if (vTrim.startsWith("{") || vTrim.startsWith("[")) {
                            // 尝试递归解析，如果成功则不添加原始值
                            Set<String> nestedResults = new HashSet<>();
                            parseJsonStream(value, nestedResults, depth + 1);

                            // 如果递归解析成功（提取到了内容），使用递归结果
                            if (!nestedResults.isEmpty()) {
                                collector.addAll(nestedResults);
                            } else {
                                // 递归解析失败，保留原始值
                                collector.add(value);
                            }
                        } else {

                            collector.add(value);

                        }
                    }
                }

                // 提取数字值（转为字符串）
                else if (token == JsonToken.VALUE_NUMBER_INT || token == JsonToken.VALUE_NUMBER_FLOAT) {
                    String numValue = parser.getText();
                    if (numValue != null && numValue.length() >= MIN_LEN) {
                        collector.add(numValue);
                    }
                }

                // 提取布尔值（转为字符串）
                else if (token == JsonToken.VALUE_TRUE || token == JsonToken.VALUE_FALSE) {
                    String boolValue = parser.getText();
                    if (boolValue != null && boolValue.length() >= MIN_LEN) {
                        collector.add(boolValue);
                    }
                }
            }
        } catch (Exception e) {

            handleTruncatedJson(content, collector, depth);
        } finally {
            if (parser != null) {
                try {
                    parser.close();
                } catch (Exception e) {
                    // 忽略关闭异常
                }
            }
        }
    }

    /**
     ◦ 处理截断的JSON

     ◦ 尝试多种修复策略

     */
    private static void handleTruncatedJson(String content, Set<String> collector, int depth) {
        if (content == null || content.trim().isEmpty()) return;

        String trimmed = content.trim();
        boolean fixed = false;

        // 策略1: 补充缺失的引号
        if (!trimmed.endsWith("\"") && !trimmed.endsWith("}") && !trimmed.endsWith("]")) {
            String fixedContent = content + "\"";
            if (tryParseFixed(fixedContent, collector, depth)) {
                fixed = true;
            }
        }

        // 策略2: 补充缺失的右括号
        if (!fixed && !trimmed.endsWith("}") && !trimmed.endsWith("]")) {
            // 统计左右括号数量
            int leftBrace = countChar(trimmed, '{');
            int rightBrace = countChar(trimmed, '}');
            int leftBracket = countChar(trimmed, '[');
            int rightBracket = countChar(trimmed, ']');

            StringBuilder fixedContent = new StringBuilder(content);

            // 补充缺失的右括号
            for (int i = 0; i < (leftBracket - rightBracket); i++) {
                fixedContent.append("]");
            }
            for (int i = 0; i < (leftBrace - rightBrace); i++) {
                fixedContent.append("}");
            }

            if (tryParseFixed(fixedContent.toString(), collector, depth)) {
                fixed = true;
            }
        }

        // 策略3: 使用正则兜底提取
        if (!fixed) {
            extractWithRegex(content, collector);
        }
    }

    /**
     ◦ 尝试解析修复后的JSON

     */
    private static boolean tryParseFixed(String fixedContent, Set<String> collector, int depth) {
        JsonParser fixedParser = null;
        try {
            fixedParser = jsonFactory.createParser(fixedContent);
            String currentFieldName = null;

            JsonToken token;
            while ((token = fixedParser.nextToken()) != null) {

                // 提取字段名
                if (token == JsonToken.FIELD_NAME) {
                    currentFieldName = fixedParser.getCurrentName();
                    if (currentFieldName != null && currentFieldName.length() >= MIN_LEN) {
                        collector.add(currentFieldName);
                    }
                }
                // 提取字符串值
                else if (token == JsonToken.VALUE_STRING) {
                    String value = fixedParser.getText();
                    if (value != null && value.length() >= MIN_LEN) {
                        String vTrim = value.trim();
                        if (vTrim.startsWith("{") || vTrim.startsWith("[")) {
                            Set<String> nestedResults = new HashSet<>();
                            parseJsonStream(value, nestedResults, depth + 1);
                            if (!nestedResults.isEmpty()) {
                                collector.addAll(nestedResults);
                            } else {
                                collector.add(value);
                            }
                        } else {
                            collector.add(value);
                        }
                    }
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (fixedParser != null) {
                try {
                    fixedParser.close();
                } catch (Exception e) {
                    // 忽略
                }
            }
        }
    }

    /**
     ◦ 使用正则表达式提取字符串

     ◦ 作为最后的兜底方案

     *
     ◦ 优化：正确处理转义引号，避免将 \" 误判为字符串结束

     */
    private static void extractWithRegex(String content, Set<String> collector) {
        // 手动解析，正确处理转义字符
        extractQuotedStrings(content, collector, '"');
        extractQuotedStrings(content, collector, '\'');

        // 提取最后一个不完整的字符串
        Matcher lastMatcher = LAST_INCOMPLETE_STRING.matcher(content);
        if (lastMatcher.find()) {
            String lastValue = lastMatcher.group(1);
            if (lastValue != null && lastValue.length() >= MIN_LEN) {
                collector.add(lastValue);
            }
        }
    }

    /**
     ◦ 手动提取引号包裹的字符串，正确处理转义字符

     *
     ◦ @param content 要解析的内容

     ◦ @param collector 结果收集器

     ◦ @param quoteChar 引号字符（" 或 '）

     */
    private static void extractQuotedStrings(String content, Set<String> collector, char quoteChar) {
        int len = content.length();
        int i = 0;

        while (i < len) {
            // 找到引号开始位置
            if (content.charAt(i) == quoteChar) {
                int start = i + 1; // 引号后的第一个字符
                i++; // 跳过开始引号

                StringBuilder value = new StringBuilder();
                boolean escaped = false;
                boolean foundEnd = false;

                // 查找结束引号，正确处理转义
                while (i < len) {
                    char c = content.charAt(i);

                    if (escaped) {
                        // 前一个字符是反斜杠，当前字符被转义
                        value.append(c);
                        escaped = false;
                    } else if (c == '\\') {
                        // 当前是反斜杠，标记转义状态
                        value.append(c);
                        escaped = true;
                    } else if (c == quoteChar) {
                        // 找到未转义的结束引号
                        foundEnd = true;
                        break;
                    } else {
                        // 普通字符
                        value.append(c);
                    }

                    i++;
                }

                // 如果找到了完整的字符串且长度符合要求
                if (foundEnd && value.length() >= MIN_LEN) {
                    collector.add(value.toString());
                }

                i++; // 跳过结束引号
            } else {
                i++;
            }
        }
    }

    /**
     ◦ 统计字符出现次数（只统计字符串外的字符，避免误判）

     *
     ◦ @param text 要统计的文本

     ◦ @param ch 要统计的字符

     ◦ @return 字符串外该字符的出现次数

     */
    private static int countChar(String text, char ch) {
        int count = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (escaped) {
                // 前一个字符是反斜杠，当前字符被转义，跳过
                escaped = false;
                continue;
            }

            if (c == '\\') {
                // 当前是反斜杠，标记转义状态
                escaped = true;
                continue;
            }

            if (c == '"') {
                // 切换字符串状态
                inString = !inString;
                continue;
            }

            // 只统计字符串外的目标字符
            if (!inString && c == ch) {
                count++;
            }
        }

        return count;
    }

    /**
     ◦ Form Data 解析 (a=b&c=d)

     */
    private static void parseFormDataStream(String content, Set<String> collector) {
        StringBuilder buffer = new StringBuilder();
        boolean isReadingValue = false;

        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            if (c == '=') {
                isReadingValue = true;
                buffer.setLength(0);
            } else if (c == '&') {
                if (isReadingValue && buffer.length() >= MIN_LEN) {
                    collector.add(buffer.toString());
                }
                isReadingValue = false;
                buffer.setLength(0);
            } else {
                if (isReadingValue) {
                    buffer.append(c);
                }
            }
        }
        // 处理末尾
        if (isReadingValue && buffer.length() >= MIN_LEN) {
            collector.add(buffer.toString());
        }
    }

    /**
     ◦ 记录 JSON 解析失败日志（抽样记录）

     ◦ 每 PARSE_FAILURE_SAMPLE_RATE 次失败记录一次

     *
     ◦ @param rawData 原始数据

     ◦ @param exception 异常信息

     */
    private static void logJsonParseFailure(String rawData, Exception exception) {
        jsonParseFailureCount++;

        // 抽样记录：每 PARSE_FAILURE_SAMPLE_RATE 次失败记录一次
        if (jsonParseFailureCount % PARSE_FAILURE_SAMPLE_RATE == 0) {
            String truncatedData = truncateData(rawData, 500);
            System.err.println("[XSS检测器] JSON解析失败 (第" + jsonParseFailureCount + "次)");
            System.err.println("  异常类型: " + exception.getClass().getSimpleName());
            System.err.println("  异常信息: " + exception.getMessage());
            System.err.println("  原始数据 (前500字符): " + truncatedData);
            System.err.println("  数据长度: " + (rawData != null ? rawData.length() : 0) + " 字符");
            System.err.println("---");
        }
    }

    /**
     ◦ 记录 FormData 解析失败日志（抽样记录）

     ◦ 每 PARSE_FAILURE_SAMPLE_RATE 次失败记录一次

     *
     ◦ @param rawData 原始数据

     ◦ @param exception 异常信息

     */
    private static void logFormParseFailure(String rawData, Exception exception) {
        formParseFailureCount++;

        // 抽样记录：每 PARSE_FAILURE_SAMPLE_RATE 次失败记录一次
        if (formParseFailureCount % PARSE_FAILURE_SAMPLE_RATE == 0) {
            String truncatedData = truncateData(rawData, 500);
            System.err.println("[XSS检测器] FormData解析失败 (第" + formParseFailureCount + "次)");
            System.err.println("  异常类型: " + exception.getClass().getSimpleName());
            System.err.println("  异常信息: " + exception.getMessage());
            System.err.println("  原始数据 (前500字符): " + truncatedData);
            System.err.println("  数据长度: " + (rawData != null ? rawData.length() : 0) + " 字符");
            System.err.println("---");
        }
    }

    /**
     ◦ 截断数据用于日志输出

     ◦ 防止日志过大，同时保留开头和结尾

     *
     ◦ @param data 原始数据

     ◦ @param maxLength 最大长度

     ◦ @return 截断后的数据（格式：开头...结尾 (共XXX字符)）

     */
    private static String truncateData(String data, int maxLength) {
        if (data == null) {
            return "null";
        }
        if (data.length() <= maxLength) {
            return data;
        }

        // 计算开头和结尾各占的长度
        // 预留 "... (共XXXXX字符)" 的空间，大约 20 个字符
        int ellipsisSpace = 20;
        int availableLength = maxLength - ellipsisSpace;
        int headLength = availableLength / 2;
        int tailLength = availableLength - headLength;

        String head = data.substring(0, headLength);
        String tail = data.substring(data.length() - tailLength);

        return head + "..." + tail ;
    }

    // =========================================================================
    // Layer 2: 溯源归一化层
    // =========================================================================

    /**
     ◦ 归一化并返回解码次数

     ◦ @param input 原始输入

     ◦ @return Map 包含 normalized (String) 和 decodeCount (Integer)

     */
    public static Map<String, Object> canonicalizeWithCount(String input) {
        String current = input;
        String previous = "";
        int iterations = 0;

        // 步骤1: 移除HTML注释（不计入解码次数）
        // 例如：<!-- comment --> 或 <!--<script>alert(1)</script>-->
        current = HTML_COMMENT_PATTERN.matcher(current).replaceAll("");

        // 步骤2: 循环解码，防止多重编码绕过
        while (!current.equals(previous) && iterations < 5) {
            previous = current;
            current = decodeUrl(current);
            current = decodeHtmlEntity(current);
            current = decodeUnicode(current);
            iterations++;
        }

        // 步骤3: 清洗干扰字符（空字节、实际的换行符、制表符等）
        // 检测是否在字符串中间清洗掉了控制字符（如 jav\tasc\tript）
        boolean hasMiddleControlChars = detectMiddleControlChars(current);
        String normalized = current.replaceAll("[\\x00\\r\\n\\t]", "");

        // 如果在字符串中间清洗掉了控制字符，增加解码次数
        // 这表明攻击者使用了控制字符混淆绕过
        if (hasMiddleControlChars) {
            iterations++;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("normalized", normalized);
        result.put("decodeCount", iterations);
        return result;
    }

    /**
     ◦ 检测字符串中间是否包含控制字符（用于混淆绕过）

     ◦ 例如：jav\tasc\tript://m.dianping.com/\ntop['e

     *
     ◦ @param input 输入字符串

     ◦ @return 如果在字符串中间（非开头结尾）包含控制字符则返回true

     */
    private static boolean detectMiddleControlChars(String input) {
        if (input == null || input.length() < 3) {
            return false;
        }

        // 检查字符串中间位置（排除开头和结尾）是否有控制字符
        for (int i = 1; i < input.length() - 1; i++) {
            char c = input.charAt(i);
            // 检测控制字符：\x00, \r, \n, \t
            if (c == '\0' || c == '\r' || c == '\n' || c == '\t') {
                // 检查前后是否有字母数字字符（表明是在单词中间）
                char prev = input.charAt(i - 1);
                char next = input.charAt(i + 1);

                // 如果前后都是字母、数字或常见符号，说明是在有意义的内容中间
                if (isAlphanumericOrCommon(prev) && isAlphanumericOrCommon(next)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     ◦ 判断字符是否为字母、数字或常见符号

     */
    private static boolean isAlphanumericOrCommon(char c) {
        return Character.isLetterOrDigit(c) ||
                c == '/' || c == ':' || c == '.' || c == '-' || c == '_' ||
                c == '[' || c == ']' || c == '(' || c == ')' || c == '\'' || c == '"' ||
                c == '<' || c == '>' || c == '=' || c == '{' || c == '}';
    }

    /**
     ◦ 移除空白字符绕过

     ◦ 将 \t \n \r \f \v 等转义序列替换为空

     *
     ◦ @param input 输入字符串

     ◦ @return 移除绕过后的字符串

     */
    public static String removeWhitespaceBypass(String input) {
        // 替换所有空白字符转义序列为空
        return input
                .replace("\\t", "")   // 制表符
                .replace("\\n", "")   // 换行符
                .replace("\\r", "")   // 回车符
                .replace("\\f", "")   // 换页符
                .replace("\\v", "");  // 垂直制表符
    }

    private static String decodeUrl(String input) {
        if (!input.contains("%")) return input;
        try {
            return URLDecoder.decode(input, "UTF-8");
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            // JDK 8 中 URLDecoder 会抛出 Checked Exception
            // 解码失败保留原样
            return input;
        } catch (Exception e) {
            return input;
        }
    }

    private static String decodeHtmlEntity(String input) {
        if (!input.contains("&")) return input;
        String temp = input;

        // JDK 8 必须使用 StringBuffer 配合 appendReplacement
        StringBuffer sb = new StringBuffer();

        // Hex Entities
        Matcher hex = HEX_ENTITY.matcher(temp);
        while (hex.find()) {
            try {
                int code = Integer.parseInt(hex.group(1), 16);
                // quoteReplacement 防止 payload 中的 $ 或 \ 导致 crash
                hex.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (Exception e) {
                // 解析失败时不替换
            }
        }
        hex.appendTail(sb);
        temp = sb.toString();

        // Decimal Entities
        sb = new StringBuffer(); // 重置 Buffer
        Matcher dec = DEC_ENTITY.matcher(temp);
        while (dec.find()) {
            try {
                int code = Integer.parseInt(dec.group(1));
                dec.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (Exception e) {
            }
        }
        dec.appendTail(sb);

        // 简单替换常用实体
        return sb.toString()
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&");
    }

    private static String decodeUnicode(String input) {
        if (!input.contains("\\u")) return input;
        StringBuffer sb = new StringBuffer();
        Matcher m = UNICODE_PATTERN.matcher(input);
        while (m.find()) {
            try {
                int code = Integer.parseInt(m.group(1), 16);
                m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (Exception e) {
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // =========================================================================
    // Layer 3: XSS风险过滤层
    // =========================================================================

    /**
     ◦ 过滤提取结果，丢弃没有XSS风险的简单字符串

     *
     ◦ 过滤规则：

     ◦ 1. 没有特殊符号（<>(){}[]等）

     ◦ 2. 中文占大部分（>= 50%）

     ◦ 3. 长度较短（<= 100字符）

     *
     ◦ @param results 提取的结果列表

     ◦ @return 过滤后的结果列表（只保留有XSS风险的数据）

     */
    public static List<Map<String, Object>> filterXssRisk(List<Map<String, Object>> results) {
        List<Map<String, Object>> filtered = new ArrayList<>();

        for (Map<String, Object> item : results) {
            String normalized = (String) item.get("normalized");

            // 判断是否有XSS风险
            if (hasXssRisk(normalized)) {
                filtered.add(item);
            }
        }

        return filtered;
    }

    /**
     ◦ 提取文本中的所有 HTML 标签

     *
     ◦ @param lowerText 小写文本

     ◦ @return 所有找到的标签集合

     */
    private static Set<String> extractAllTags(String lowerText) {
        Matcher tagMatcher = HTML_TAG_PATTERN.matcher(lowerText);
        Set<String> foundTags = new HashSet<>();
        while (tagMatcher.find()) {
            String tagName = tagMatcher.group(1).toLowerCase();
            if (!tagName.isEmpty()) {
                foundTags.add("<" + tagName);
            }
        }
        return foundTags;
    }

    /**
     ◦ 检查 img 标签是否包含危险属性

     ◦ 只检查 img 标签内的属性，不检查其他标签

     *
     ◦ @param lowerText 小写文本

     ◦ @return true 表示 img 标签包含危险属性，false 表示安全

     */
    private static boolean imgHasDangerousAttrs(String lowerText) {
        // 使用预编译的正则提取所有 img 标签
        Matcher imgMatcher = IMG_TAG_PATTERN.matcher(lowerText);

        // 危险属性列表
        String[] dangerousAttrs = {
                "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
                "onblur=", "onchange=", "onsubmit=", "oninput=", "onanimationend=",
                "javascript:", "data:text/html", "vbscript:",
                "eval(", "alert(", "prompt(", "confirm(",
                "document.cookie", "document.write", "innerhtml", "outerhtml"
        };

        // 检查每个 img 标签
        while (imgMatcher.find()) {
            String imgTag = imgMatcher.group();
            // 使用 indexOf 而不是 contains，性能更好
            for (String attr : dangerousAttrs) {
                if (imgTag.indexOf(attr) != -1) {
                    return true; // img 标签包含危险属性
                }
            }
        }
        return false;
    }

    /**
     ◦ 检查 href 属性中的 URL 是否安全

     ◦ 检查流程：

     ◦ 1. 如果包含 javascript:，直接判定为黑名单（危险）

     ◦ 2. 如果是常用的 CDN 和公司域名，则认为安全

     ◦ 3. 排除包含 s3plus 的 URL

     *
     ◦ @param hrefValue href 属性的值

     ◦ @return true 表示 URL 安全，false 表示不安全或需要进一步检查

     */
    private static boolean isHrefUrlSafe(String hrefValue) {
        if (hrefValue == null || hrefValue.isEmpty()) {
            return true; // 空 href 是安全的
        }

        String lowerHref = hrefValue.toLowerCase();

        // 【黑名单条件】如果包含 javascript:，直接判定为不安全
        if (lowerHref.contains("javascript:")) {
            return false;
        }

        // 【黑名单条件】如果包含 s3plus，直接判定为不安全
        if (lowerHref.contains("s3plus")) {
            return false;
        }

        // 【黑名单条件】其他危险伪协议
        if (lowerHref.startsWith("data:text/html") || lowerHref.startsWith("vbscript:")) {
            return false;
        }

        // 【白名单域名】常用的 CDN 和公司域名
        String[] whitelistDomains = {
                // 美团相关域名
                "meituan.com",
                "sankuai.com",
                "dianping.com",
                // 常用 CDN
                "cdn.jsdelivr.net",
                "cdnjs.cloudflare.com",
                "unpkg.com",
                "cdn.bootcdn.net",
                "lib.baomitu.com",
                "code.jquery.com",
                "ajax.googleapis.com",
                "ajax.aspnetcdn.com",
                "maxcdn.bootstrapcdn.com",
                "cdn.staticfile.org",
                "fonts.googleapis.com",
                "fonts.gstatic.com",
                // 美团内部 CDN
                "p0.meituan.net",
                "p1.meituan.net",

        };

        // 检查是否匹配白名单域名
        for (String domain : whitelistDomains) {
            if (lowerHref.contains(domain)) {
                return true; // 匹配白名单域名，认为安全
            }
        }

        // 检查是否是相对 URL（不包含协议）
        if (!lowerHref.contains("://")) {
            return true; // 相对 URL 是安全的
        }

        // 其他情况需要进一步检查
        return false;
    }

    /**
     ◦ 检查 a 标签是否包含危险属性

     ◦ a 标签的危险主要在于 href 属性中的危险伪协议和事件处理器

     ◦ 只检查 a 标签内的属性，不检查其他标签

     *
     ◦ @param lowerText 小写文本

     ◦ @return true 表示 a 标签包含危险属性，false 表示安全

     */
    private static boolean aTagHasDangerousAttrs(String lowerText) {
        // 使用预编译的正则提取所有 a 标签
        Matcher aMatcher = A_TAG_PATTERN.matcher(lowerText);

        // 【第一步】检查事件处理器
        String[] eventHandlers = {
                "onclick=", "onmouseover=", "onfocus=", "onblur=",
                "onmouseenter=", "onmouseleave=", "ondblclick=",
                "onmousedown=", "onmouseup=", "oncontextmenu=",
                "onload=", "onerror=", "onchange=", "onsubmit=",
                "oninput=", "onkeydown=", "onkeyup=", "onkeypress=",
                "ondrag=", "ondrop=", "onpaste=", "oncopy=", "oncut="
        };

        // 【第二步】检查危险伪协议和其他危险内容
        String[] dangerousPatterns = {
                "data:text/html", "vbscript:",
                "eval(", "alert(", "prompt(", "confirm(",
                "document.cookie", "document.write", "innerhtml", "outerhtml"
        };

        // 【第三步】其他可能包含 URL 的属性
        String[] urlAttributes = {"data", "formaction", "poster"};

        // 检查每个 a 标签
        while (aMatcher.find()) {
            String aTag = aMatcher.group();

            // 检查事件处理器 - 使用 indexOf 避免不必要的对象创建
            for (String event : eventHandlers) {
                if (aTag.indexOf(event) != -1) {
                    return true; // a 标签包含事件处理器，危险
                }
            }

            // 检查危险伪协议和其他危险内容
            for (String pattern : dangerousPatterns) {
                if (aTag.indexOf(pattern) != -1) {
                    return true; // a 标签包含危险内容
                }
            }

            // 特殊处理 href 属性中的危险内容
            if (aTag.indexOf("href") != -1) {
                String hrefValue = extractAttributeValue(aTag, "href");
                if (hrefValue != null && !isHrefUrlSafe(hrefValue)) {
                    return true; // href 不安全
                }
            }

            // 检查其他可能包含 URL 的属性
            for (String attr : urlAttributes) {
                if (aTag.indexOf(attr + "=") != -1) {
                    String attrValue = extractAttributeValue(aTag, attr);
                    if (attrValue != null && !isHrefUrlSafe(attrValue)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     ◦ 从 HTML 标签中提取属性值

     ◦ 支持单引号、双引号和无引号的属性值

     *
     ◦ @param tag HTML 标签字符串

     ◦ @param attrName 属性名

     ◦ @return 属性值，如果不存在则返回 null

     */
    private static String extractAttributeValue(String tag, String attrName) {
        // 构建属性匹配模式，支持多种格式
        // 格式1: href="value"
        // 格式2: href='value'
        // 格式3: href=value（无引号）

        String lowerTag = tag.toLowerCase();
        String lowerAttrName = attrName.toLowerCase();

        // 查找属性名的位置
        int attrPos = lowerTag.indexOf(lowerAttrName + "=");
        if (attrPos == -1) {
            return null;
        }

        int valueStart = attrPos + lowerAttrName.length() + 1;
        if (valueStart >= tag.length()) {
            return null;
        }

        char firstChar = tag.charAt(valueStart);

        // 情况1: 双引号
        if (firstChar == '"') {
            int valueEnd = tag.indexOf('"', valueStart + 1);
            if (valueEnd != -1) {
                return tag.substring(valueStart + 1, valueEnd);
            }
        }
        // 情况2: 单引号
        else if (firstChar == '\'') {
            int valueEnd = tag.indexOf('\'', valueStart + 1);
            if (valueEnd != -1) {
                return tag.substring(valueStart + 1, valueEnd);
            }
        }
        // 情况3: 无引号（值到空格或 > 为止）
        else {
            int valueEnd = valueStart;
            while (valueEnd < tag.length() && tag.charAt(valueEnd) != ' ' && tag.charAt(valueEnd) != '>') {
                valueEnd++;
            }
            if (valueEnd > valueStart) {
                return tag.substring(valueStart, valueEnd);
            }
        }

        return null;
    }

    /**
     ◦ 判断字符串是否只包含安全的HTML标签（不含任何危险属性）

     ◦ 如果只包含安全标签且没有危险属性，则不认为是XSS

     *
     ◦ 检测流程：

     ◦ 1. 提取所有标签

     ◦ 2. 对 img 标签进行特殊处理：如果没有危险属性，从标签列表中移除

     ◦ 3. 检查剩余标签是否都在绝对安全列表中

     ◦ 4. 检查剩余标签是否都在安全列表中

     *
     ◦ @param text 要检查的文本

     ◦ @return true 表示只包含安全标签且无危险属性，false 表示包含其他内容

     */
    private static boolean isOnlySafeHtmlTags(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        String lowerText = text.toLowerCase();

        String[] dangerousAttributes = {
                "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
                "onblur=", "onchange=", "onsubmit=", "oninput=", "onanimationend=",
                "javascript:", "data:text/html", "vbscript:",
                "eval(",
                "document.cookie", "document.write", "innerhtml", "outerhtml"
        };

        for (String attr : dangerousAttributes) {
            if (lowerText.contains(attr)) {
                return false; // 包含危险属性，不是纯安全标签
            }
        }

        // 【步骤1】提取所有标签
        Set<String> foundTags = extractAllTags(lowerText);

        // 如果没有找到任何标签，返回false
        if (foundTags.isEmpty()) {
            return false;
        }

        // 【步骤2】对 img 标签进行特殊处理
        if (foundTags.contains("<img")) {
            // 检查 img 标签是否包含危险属性
            if (!imgHasDangerousAttrs(lowerText)) {
                // img 标签安全，从标签列表中移除
                foundTags.remove("<img");
            } else {
                // img 标签包含危险属性，直接返回 false
                return false;
            }
        }

        // 【步骤2.5】对 a 标签进行特殊处理
        if (foundTags.contains("<a")) {
            // 检查 a 标签是否包含危险属性
            if (!aTagHasDangerousAttrs(lowerText)) {
                // a 标签安全，从标签列表中移除
                foundTags.remove("<a");
            } else {
                // a 标签包含危险属性，直接返回 false
                return false;
            }
        }

        // 【步骤3】如果移除 img 和 a 标签后没有其他标签，判定为安全
        if (foundTags.isEmpty()) {
            return true;
        }

        // 【步骤4】检查剩余标签是否都在绝对安全列表中
        boolean allAbsolutelySafe = true;
        for (String tag : foundTags) {
            if (!ABSOLUTELY_SAFE_TAGS.contains(tag)) {
                allAbsolutelySafe = false;
                break;
            }
        }

        if (allAbsolutelySafe) {
            return true; // 所有标签都在绝对安全列表中
        }

        // 【步骤5】快速检查：如果包含明显的危险属性，直接返回false


        // 【步骤6】检查所有找到的标签是否都在安全列表中
        for (String tag : foundTags) {
            if (!SAFE_HTML_TAGS.contains(tag)) {
                return false; // 发现不安全的标签
            }
        }

        // 【步骤7】使用预编译的正则移除所有标签，检查是否还有其他可疑内容
        String withoutTags = HTML_TAG_REMOVE_PATTERN.matcher(lowerText).replaceAll("").trim();

        // 如果移除标签后只剩下空白或纯文本（不包含特殊字符），则认为是安全的
        if (withoutTags.isEmpty()) {
            return true; // 完全空白，安全
        }

        // 使用预编译的正则检测是否只包含纯文本
        if (SAFE_TEXT_PATTERN.matcher(withoutTags).matches()) {
            return true; // 只包含纯文本，安全
        }

        // 如果不匹配纯文本正则，检查中文占比
        int chineseCount = 0;
        int totalCount = withoutTags.length();

        for (int i = 0; i < totalCount; i++) {
            char c = withoutTags.charAt(i);
            // 中文字符范围：\u4E00-\u9FFF
            if (c >= 0x4E00 && c <= 0x9FFF) {
                chineseCount++;
            }
        }

        if (chineseCount > 0) {
            double chineseRatio = (double) chineseCount / totalCount;
            if (chineseRatio >= 0.6) {
                return true; // 中文占 60% 以上，判定为安全
            }
        }

        return false; // 包含可疑字符，不安全
    }

    /**
     ◦ 检查字符串是否符合 XSS 特征

     ◦ 综合检查：长度、特殊符号类型等

     *
     ◦ @param text 要检查的文本

     ◦ @return true 表示符合 XSS 特征，false 表示不符合（应该过滤）

     */
    private static boolean hasXssCharacteristics(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        // 【检查1】长度检查：< 15 字符直接过滤
        if (text.length() < 15) {
            return false;
        }

        // 【检查1.5】关键符号检查：必须包含 <, (, [ 中的至少 2 个
        // 这些是 XSS 攻击的核心符号，需要至少 2 个才符合 XSS 特征
        int keySymbolCount = 0;
        if (text.contains("<")) keySymbolCount++;
        if (text.contains("(")) keySymbolCount++;
        if (text.contains("[")) keySymbolCount++;

        if (keySymbolCount < 2) {
            return false; // 关键符号少于 2 个，不符合 XSS 特征
        }

        // 【检查2】统计特殊符号类型
        boolean hasAngleBrackets = false;      // < >
        boolean hasParentheses = false;        // ( )
        boolean hasSquareBrackets = false;     // [ ]
        boolean hasCurlyBraces = false;        // { }
        boolean hasDoubleQuotes = false;       // "

        boolean hasBackticks = false;          // ` (单独作为一个类型)
        boolean hasEquals = false;             // =

        boolean hasColon = false;              // :
        boolean hasSemicolon = false;          // ;
        boolean hasSlash = false;              // / \
        boolean hasOtherSpecial = false;       // 其他特殊符号

        for (char c : text.toCharArray()) {
            switch (c) {
                case '<':
                case '>':
                    hasAngleBrackets = true;
                    break;
                case '(':
                case ')':
                    hasParentheses = true;
                    break;
                case '[':
                case ']':
                    hasSquareBrackets = true;
                    break;
                case '{':
                case '}':
                    hasCurlyBraces = true;
                    break;
                case '"':
                case '\'':
                    hasDoubleQuotes = true;
                    break;


                case '`':
                    hasBackticks = true;
                    break;
                case '=':
                    hasEquals = true;
                    break;

                case '+':
                    hasColon = true;
                    break;
                case ',':
                    hasSemicolon = true;
                    break;
                case '/':
                case '\\':
                    hasSlash = true;
                    break;
                default:
                    // 其他特殊符号（非字母数字、非空白）
                    if (!Character.isLetterOrDigit(c) && !Character.isWhitespace(c)) {
                        hasOtherSpecial = true;
                    }
            }
        }

        // 【检查3】统计特殊符号类型数量
        int typeCount = 0;
        if (hasAngleBrackets) typeCount++;
        if (hasParentheses) typeCount++;
        if (hasSquareBrackets) typeCount++;
        if (hasCurlyBraces) typeCount++;
        if (hasDoubleQuotes) typeCount++;

        if (hasBackticks) typeCount++;
        if (hasEquals) typeCount++;

        if (hasColon) typeCount++;
        if (hasSemicolon) typeCount++;
        if (hasSlash) typeCount++;
        if (hasOtherSpecial) typeCount++;

        // 【检查4】特殊符号类型少于 2 种则过滤
        if (typeCount < 3) {
            return false;
        }

        // 通过所有检查，符合 XSS 特征
        return true;
    }

    /**
     ◦ 判断字符串是否有XSS风险

     *
     ◦ @param text 要检查的文本

     ◦ @return true 表示有XSS风险，false 表示是简单字符串

     */
    private static boolean hasXssRisk(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        // 【快速过滤】跳过 WebKit Form Boundary
        if (text.startsWith("------WebKitFormBoundary")) {
            return false;
        }

        // 【综合过滤】检查是否符合 XSS 特征（长度、特殊符号类型等）
        if (!hasXssCharacteristics(text)) {
            return false;
        }

        // 性能优化：按照从快到慢的顺序检查

        // 0. 最快检查：过滤空结构（[], {}, "", '', ``等）
        String trimmed = text.trim();
        if (trimmed.equals("[]") || trimmed.equals("{}") ||
                trimmed.equals("\"\"") || trimmed.equals("''") ||
                trimmed.equals("``") || trimmed.equals("()")) {
            return false; // 空结构，不是XSS
        }

        // 0.1 检查是否只包含空白和符号（没有实际内容）
        // 例如：[ ]、{ }、[ { } ]等
        String contentOnly = trimmed.replaceAll("[\\s\\[\\]{}()'\"`]", "");
        if (contentOnly.isEmpty()) {
            return false; // 只有符号和空白，没有实际内容
        }

        // 0.15 检查是否只包含安全的HTML标签
        if (isOnlySafeHtmlTags(text)) {
            return false; // 只包含安全标签，不是XSS
        }

        // 0.2 最快检查：是否包含XSS核心符号（< > ( ) = [ ] ' " { }）
        // 如果不包含这些核心符号，基本不可能是XSS攻击
        // 这个检查最快，可以快速过滤掉90%的无害数据
        if (!XSS_CORE_PATTERN.matcher(text).find()) {
            return false; // 不包含核心符号，直接判定为简单字符串
        }

        // 1. 快速检查：纯字母数字（使用预编译正则，带锚点更快）
        if (ALPHANUMERIC_PATTERN.matcher(text).matches()) {
            return false; // 纯字母数字，是简单字符串
        }

        // 2. 快速检查：纯中文（使用预编译正则，带锚点更快）
        if (CHINESE_PATTERN.matcher(text).matches()) {
            return false; // 纯中文，是简单字符串
        }

        // 3. 中速检查：计算中文字符占比（只在前面检查都通过后才执行）
        int chineseCount = 0;
        int totalCount = text.length();

        for (int i = 0; i < totalCount; i++) {
            char c = text.charAt(i);
            // 中文字符范围：\u4E00-\u9FFF
            if (c >= 0x4E00 && c <= 0x9FFF) {
                chineseCount++;
            }
        }

        // 如果中文占比 >= 60% 且没有特殊符号，判定为简单字符串
        if (chineseCount > 0) {
            double chineseRatio = (double) chineseCount / totalCount;
            if (chineseRatio >= 0.6) {
                return false; // 中文占大部分，是简单字符串
            }
        }

        // 4. 到达这里说明：
        //    - 不是空结构
        //    - 包含实际内容
        //    - 包含XSS核心符号（< > ( ) = [ ] ' " { }）
        //    - 不是纯字母数字
        //    - 不是纯中文
        //    - 中文占比 < 60%
        //    → 判定为有XSS风险
        return true;
    }

    // 检测阈值
    private static final int XSS_DETECTION_THRESHOLD = 25; // XSS检测阈值
    private static final int DECODE_BONUS_PER_LAYER = 10;   // 每层解码的加分

    // =========================================================================
    // 通用入口方法
    // =========================================================================

    /**
     ◦ 通用入口：一站式XSS检测（使用默认阈值）

     *
     ◦ 功能流程：

     ◦ 1. 提取和归一化：解析JSON/Form/Raw数据，进行多层解码

     ◦ 2. 风险过滤：过滤掉明显无害的数据（纯字母数字、纯中文等）

     ◦ 3. XSS检测：对有风险的数据进行深度XSS检测

     *
     ◦ @param rawData 原始输入数据（可以是JSON、Form或普通字符串）

     ◦ @return XSS检测结果，包含详细的风险信息

     */
    public static Map<String, Object> detectXss(String rawData) {
        return detectXss(rawData, XSS_DETECTION_THRESHOLD);
    }

    /**
     ◦ 通用入口：一站式XSS检测（支持自定义阈值）

     *
     ◦ 功能流程：

     ◦ 1. 提取和归一化：解析JSON/Form/Raw数据，进行多层解码

     ◦ 2. 风险过滤：过滤掉明显无害的数据（纯字母数字、纯中文等）

     ◦ 3. XSS检测：对有风险的数据进行深度XSS检测

     *
     ◦ @param rawData 原始输入数据（可以是JSON、Form或普通字符串）

     ◦ @param threshold 自定义告警阈值（分数超过此阈值则判定为XSS）

     ◦ @return XSS检测结果，包含详细的风险信息

     *
     ◦ 返回结果包含以下字段：

     ◦ - isXss (Boolean): 是否检测到XSS

     ◦ - riskScore (Integer): 风险评分

     ◦ - originalRiskScore (Integer): 原始评分（不含解码加分）

     ◦ - decodeBonus (Integer): 解码加分

     ◦ - decodeCount (Integer): 解码次数

     ◦ - hasMaliciousPattern (Boolean): 是否包含恶意模式

     ◦ - dataType (String): 数据类型（JSON/FORM/RAW）

     ◦ - threshold (Integer): 使用的阈值

     ◦ - maxRiskNormalized (String): 最高风险的归一化内容

     ◦ - totalFragments (Integer): 总片段数

     ◦ - xssFragmentsCount (Integer): XSS片段数

     ◦ - xssFragments (List): 所有XSS片段的详细信息

     */
    public static Map<String, Object> detectXss(String rawData, int threshold) {
        // 步骤1: 提取和归一化
        List<Map<String, Object>> extractedData = extract(rawData);

        // 如果提取失败或为空，返回安全结果
        if (extractedData == null || extractedData.isEmpty()) {
            return createSafeResult(threshold);
        }

        // 步骤2: 风险过滤（过滤掉明显无害的数据）
        List<Map<String, Object>> filteredData = filterXssRisk(extractedData);

        // 如果过滤后没有数据，返回安全结果
        if (filteredData == null || filteredData.isEmpty()) {
            Map<String, Object> result = createSafeResult(threshold);
            result.put("totalFragments", extractedData.size());
            result.put("filteredFragments", extractedData.size() - filteredData.size());
            return result;
        }

        // 步骤3: XSS检测
        Map<String, Object> result = detectXssInExtractedData(filteredData, threshold);

        // 添加过滤统计信息
        result.put("originalFragments", extractedData.size());
        result.put("filteredFragments", extractedData.size() - filteredData.size());

        return result;
    }

    // =========================================================================
    // XSS检测核心方法
    // =========================================================================

    /**
     ◦ 主入口：检测提取后的数据列表中的XSS（使用默认阈值）

     *
     ◦ @param extractedDataList 提取后的数据列表

     ◦ @return XSS检测结果

     */
    public static Map<String, Object> detectXssInExtractedData(List<Map<String, Object>> extractedDataList) {
        return detectXssInExtractedData(extractedDataList, XSS_DETECTION_THRESHOLD);
    }

    /**
     ◦ 主入口：检测提取后的数据列表中的XSS（支持自定义阈值）

     *
     ◦ @param extractedDataList 提取后的数据列表

     ◦ @param threshold 自定义告警阈值（分数超过此阈值则判定为XSS）

     ◦ @return XSS检测结果

     */
    public static Map<String, Object> detectXssInExtractedData(List<Map<String, Object>> extractedDataList, int threshold) {
        if (extractedDataList == null || extractedDataList.isEmpty()) {
            return createSafeResult(threshold);
        }

        // 用于存储最高风险的结果
        Map<String, Object> maxRiskResult = createSafeResult(threshold);
        int maxRiskScore = 0;
        String maxRiskNormalized = "";
        int maxRiskDecodeCount = 1;
        String maxRiskType = "";

        // 用于存储所有检测到XSS的片段
        List<Map<String, Object>> xssFragments = new ArrayList<>();

        // 遍历所有提取的数据片段
        for (Map<String, Object> dataItem : extractedDataList) {
            String normalized = (String) dataItem.get("normalized");
            Integer decodeCount = (Integer) dataItem.get("decodeCount");
            String type = (String) dataItem.get("type");

            // 跳过空数据
            if (normalized == null || normalized.trim().isEmpty()) {
                continue;
            }

            // 默认解码次数为1（未解码）
            if (decodeCount == null) {
                decodeCount = 1;
            }

            // 快速预检查：如果是安全的JavaScript表达式，跳过
            if (isSafeJavaScriptExpression(normalized.toLowerCase())) {
                continue;
            }

            // 计算解码加分：每多解码一次，加5分
            // decodeCount=1 表示未解码，加分=0
            // decodeCount=2 表示解码1次，加分=5
            // decodeCount=3 表示解码2次，加分=10
            int decodeBonus = (decodeCount - 1) * DECODE_BONUS_PER_LAYER;

            // 执行XSS检测
            Map<String, Object> result = detectXssCore(normalized);

            // 添加解码加分
            int originalScore = (Integer) result.get("riskScore");
            int adjustedScore = originalScore + decodeBonus;

            // 重新判断是否为XSS（考虑解码加分后，使用自定义阈值）
            boolean isXss = adjustedScore > threshold ||
                    ((Boolean) result.get("hasMaliciousPattern"));

            // 如果检测到XSS，记录详细信息
            if (isXss) {
                Map<String, Object> xssFragment = new HashMap<>();
                xssFragment.put("normalized", normalized);
                xssFragment.put("decodeCount", decodeCount);
                xssFragment.put("type", type);
                xssFragment.put("originalScore", originalScore);
                xssFragment.put("decodeBonus", decodeBonus);
                xssFragment.put("adjustedScore", adjustedScore);
                xssFragment.put("hasMaliciousPattern", result.get("hasMaliciousPattern"));
                xssFragment.put("threshold", threshold);
                xssFragments.add(xssFragment);
            }

            // 保留最高风险的结果
            if (adjustedScore > maxRiskScore) {
                maxRiskScore = adjustedScore;
                maxRiskResult = result;
                maxRiskResult.put("riskScore", adjustedScore);
                maxRiskResult.put("originalRiskScore", originalScore);
                maxRiskResult.put("decodeBonus", decodeBonus);
                maxRiskResult.put("decodeCount", decodeCount);
                maxRiskResult.put("dataType", type);
                maxRiskResult.put("isXss", isXss);
                maxRiskResult.put("threshold", threshold);
                maxRiskNormalized = normalized;
                maxRiskDecodeCount = decodeCount;
                maxRiskType = type;
            }
        }

        // 添加汇总信息
        maxRiskResult.put("maxRiskNormalized", maxRiskNormalized);
        maxRiskResult.put("maxRiskDecodeCount", maxRiskDecodeCount);
        maxRiskResult.put("maxRiskType", maxRiskType);
        maxRiskResult.put("totalFragments", extractedDataList.size());
        maxRiskResult.put("xssFragmentsCount", xssFragments.size());
        maxRiskResult.put("xssFragments", xssFragments);
        maxRiskResult.put("threshold", threshold);

        return maxRiskResult;
    }

    /**
     ◦ 创建安全结果（使用默认阈值）

     */
    private static Map<String, Object> createSafeResult() {
        return createSafeResult(XSS_DETECTION_THRESHOLD);
    }

    /**
     ◦ 创建安全结果（支持自定义阈值）

     *
     ◦ @param threshold 使用的阈值

     */
    private static Map<String, Object> createSafeResult(int threshold) {
        Map<String, Object> result = new HashMap<>();
        result.put("isXss", false);
        result.put("riskLevel", "none");
        result.put("riskScore", 0);
        result.put("originalRiskScore", 0);
        result.put("decodeBonus", 0);
        result.put("decodeCount", 1);
        result.put("hasMaliciousPattern", false);
        result.put("maxRiskNormalized", "");
        result.put("maxRiskDecodeCount", 1);
        result.put("maxRiskType", "");
        result.put("totalFragments", 0);
        result.put("xssFragmentsCount", 0);
        result.put("xssFragments", new ArrayList<>());
        result.put("threshold", threshold);
        return result;
    }

    // 安全JavaScript表达式白名单
    private static final List<String> SAFE_JS_WHITELIST = new ArrayList<>();

    // 安全HTML标签白名单（仅包含标签名，不包含属性）
    private static final Set<String> SAFE_HTML_TAGS = new HashSet<>();

    // 绝对安全的标签列表（这些标签本身不能执行代码，即使有任何属性也是安全的）
    // 如果只包含这些标签，直接过滤掉，不需要检查属性
    private static final Set<String> ABSOLUTELY_SAFE_TAGS = new HashSet<>();

    // 危险模式列表（统一管理，用于检测和占比计算）
    // 格式：关键字 -> 权重分数
    private static final Map<String, Integer> DANGEROUS_PATTERNS = new HashMap<>();

    static {
        // javascript: 的合法使用
        SAFE_JS_WHITELIST.add("javascript:void(0)");
        SAFE_JS_WHITELIST.add("javascript:void(false)");
        SAFE_JS_WHITELIST.add("javascript:;");
        SAFE_JS_WHITELIST.add("javascript:return false");
        SAFE_JS_WHITELIST.add("javascript:history.back()");
        SAFE_JS_WHITELIST.add("javascript:history.forward()");
        SAFE_JS_WHITELIST.add("javascript:location.reload()");
        SAFE_JS_WHITELIST.add("javascript:window.close()");

        // ===== 绝对安全的标签列表 =====
        // 这些标签本身不能执行代码，即使有任何属性也是安全的
        // 如果只包含这些标签，直接过滤掉，不需要检查属性
        ABSOLUTELY_SAFE_TAGS.add("<p");
        ABSOLUTELY_SAFE_TAGS.add("<br");
        ABSOLUTELY_SAFE_TAGS.add("<hr");
        ABSOLUTELY_SAFE_TAGS.add("<h1");
        ABSOLUTELY_SAFE_TAGS.add("<h2");
        ABSOLUTELY_SAFE_TAGS.add("<h3");
        ABSOLUTELY_SAFE_TAGS.add("<h4");
        ABSOLUTELY_SAFE_TAGS.add("<h5");
        ABSOLUTELY_SAFE_TAGS.add("<h6");
        ABSOLUTELY_SAFE_TAGS.add("<ul");
        ABSOLUTELY_SAFE_TAGS.add("<ol");
        ABSOLUTELY_SAFE_TAGS.add("<li");
        ABSOLUTELY_SAFE_TAGS.add("<table");
        ABSOLUTELY_SAFE_TAGS.add("<tr");
        ABSOLUTELY_SAFE_TAGS.add("<td");
        ABSOLUTELY_SAFE_TAGS.add("<th");
        ABSOLUTELY_SAFE_TAGS.add("<thead");
        ABSOLUTELY_SAFE_TAGS.add("<tbody");
        ABSOLUTELY_SAFE_TAGS.add("<tfoot");
        ABSOLUTELY_SAFE_TAGS.add("<strong");
        ABSOLUTELY_SAFE_TAGS.add("<em");
        ABSOLUTELY_SAFE_TAGS.add("<b");
        ABSOLUTELY_SAFE_TAGS.add("<i");
        ABSOLUTELY_SAFE_TAGS.add("<u");
        ABSOLUTELY_SAFE_TAGS.add("<s");
        ABSOLUTELY_SAFE_TAGS.add("<strike");
        ABSOLUTELY_SAFE_TAGS.add("<code");
        ABSOLUTELY_SAFE_TAGS.add("<pre");
        ABSOLUTELY_SAFE_TAGS.add("<blockquote");
        ABSOLUTELY_SAFE_TAGS.add("<small");
        ABSOLUTELY_SAFE_TAGS.add("<del");
        ABSOLUTELY_SAFE_TAGS.add("<ins");
        ABSOLUTELY_SAFE_TAGS.add("<sub");
        ABSOLUTELY_SAFE_TAGS.add("<sup");
        ABSOLUTELY_SAFE_TAGS.add("<caption");
        ABSOLUTELY_SAFE_TAGS.add("<col");
        ABSOLUTELY_SAFE_TAGS.add("<dd");
        ABSOLUTELY_SAFE_TAGS.add("<dt");
        ABSOLUTELY_SAFE_TAGS.add("<dl");
        ABSOLUTELY_SAFE_TAGS.add("<kbd");
        ABSOLUTELY_SAFE_TAGS.add("<samp");
        ABSOLUTELY_SAFE_TAGS.add("<var");
        ABSOLUTELY_SAFE_TAGS.add("<abbr");
        ABSOLUTELY_SAFE_TAGS.add("<cite");
        ABSOLUTELY_SAFE_TAGS.add("<q");
        ABSOLUTELY_SAFE_TAGS.add("<wbr");
        ABSOLUTELY_SAFE_TAGS.add("<mark");
        ABSOLUTELY_SAFE_TAGS.add("<time");
        ABSOLUTELY_SAFE_TAGS.add("<span");
        ABSOLUTELY_SAFE_TAGS.add("<div");
        ABSOLUTELY_SAFE_TAGS.add("<section");
        ABSOLUTELY_SAFE_TAGS.add("<article");
        ABSOLUTELY_SAFE_TAGS.add("<header");
        ABSOLUTELY_SAFE_TAGS.add("<footer");
        ABSOLUTELY_SAFE_TAGS.add("<nav");
        ABSOLUTELY_SAFE_TAGS.add("<aside");
        ABSOLUTELY_SAFE_TAGS.add("<main");
        ABSOLUTELY_SAFE_TAGS.add("<figure");
        ABSOLUTELY_SAFE_TAGS.add("<figcaption");
        ABSOLUTELY_SAFE_TAGS.add("<details");
        ABSOLUTELY_SAFE_TAGS.add("<summary");
        ABSOLUTELY_SAFE_TAGS.add("<fieldset");
        ABSOLUTELY_SAFE_TAGS.add("<legend");
        ABSOLUTELY_SAFE_TAGS.add("<label");
        ABSOLUTELY_SAFE_TAGS.add("<meter");
        ABSOLUTELY_SAFE_TAGS.add("<progress");
        ABSOLUTELY_SAFE_TAGS.add("<output");
        ABSOLUTELY_SAFE_TAGS.add("<address");
        ABSOLUTELY_SAFE_TAGS.add("<hgroup");
        ABSOLUTELY_SAFE_TAGS.add("<noscript");
        ABSOLUTELY_SAFE_TAGS.add("<template");
        ABSOLUTELY_SAFE_TAGS.add("<bdi");
        ABSOLUTELY_SAFE_TAGS.add("<bdo");
        ABSOLUTELY_SAFE_TAGS.add("<dfn");
        ABSOLUTELY_SAFE_TAGS.add("<rp");
        ABSOLUTELY_SAFE_TAGS.add("<rt");
        ABSOLUTELY_SAFE_TAGS.add("<ruby");
        ABSOLUTELY_SAFE_TAGS.add("<colgroup");

        // ===== 安全HTML标签白名单 =====
        // 这些标签本身不具有XSS风险，即使出现在数据中也不应该被标记为XSS
        SAFE_HTML_TAGS.add("<p");
        SAFE_HTML_TAGS.add("<div");
        SAFE_HTML_TAGS.add("<span");
        SAFE_HTML_TAGS.add("<a");
        SAFE_HTML_TAGS.add("<img");
        SAFE_HTML_TAGS.add("<br");
        SAFE_HTML_TAGS.add("<hr");
        SAFE_HTML_TAGS.add("<h1");
        SAFE_HTML_TAGS.add("<h2");
        SAFE_HTML_TAGS.add("<h3");
        SAFE_HTML_TAGS.add("<h4");
        SAFE_HTML_TAGS.add("<h5");
        SAFE_HTML_TAGS.add("<h6");
        SAFE_HTML_TAGS.add("<ul");
        SAFE_HTML_TAGS.add("<ol");
        SAFE_HTML_TAGS.add("<li");
        SAFE_HTML_TAGS.add("<table");
        SAFE_HTML_TAGS.add("<tr");
        SAFE_HTML_TAGS.add("<td");
        SAFE_HTML_TAGS.add("<th");
        SAFE_HTML_TAGS.add("<thead");
        SAFE_HTML_TAGS.add("<tbody");
        SAFE_HTML_TAGS.add("<tfoot");
        SAFE_HTML_TAGS.add("<strong");
        SAFE_HTML_TAGS.add("<em");
        SAFE_HTML_TAGS.add("<b");
        SAFE_HTML_TAGS.add("<i");
        SAFE_HTML_TAGS.add("<u");
        SAFE_HTML_TAGS.add("<s");
        SAFE_HTML_TAGS.add("<strike");
        SAFE_HTML_TAGS.add("<code");
        SAFE_HTML_TAGS.add("<pre");
        SAFE_HTML_TAGS.add("<blockquote");
        SAFE_HTML_TAGS.add("<font");  // 已废弃但安全
        SAFE_HTML_TAGS.add("<center");  // 已废弃但安全
        SAFE_HTML_TAGS.add("<big");  // 已废弃但安全
        SAFE_HTML_TAGS.add("<small");
        SAFE_HTML_TAGS.add("<form");
        SAFE_HTML_TAGS.add("<input");
        SAFE_HTML_TAGS.add("<button");
        SAFE_HTML_TAGS.add("<label");
        SAFE_HTML_TAGS.add("<select");
        SAFE_HTML_TAGS.add("<option");
        SAFE_HTML_TAGS.add("<textarea");
        SAFE_HTML_TAGS.add("<audio");
        SAFE_HTML_TAGS.add("<video");
        SAFE_HTML_TAGS.add("<source");
        SAFE_HTML_TAGS.add("<track");
        SAFE_HTML_TAGS.add("<canvas");
        SAFE_HTML_TAGS.add("<svg");
        SAFE_HTML_TAGS.add("<path");
        SAFE_HTML_TAGS.add("<circle");
        SAFE_HTML_TAGS.add("<rect");
        SAFE_HTML_TAGS.add("<line");
        SAFE_HTML_TAGS.add("<text");
        SAFE_HTML_TAGS.add("<g");
        SAFE_HTML_TAGS.add("<defs");
        SAFE_HTML_TAGS.add("<style");
        SAFE_HTML_TAGS.add("<link");
        SAFE_HTML_TAGS.add("<meta");
        SAFE_HTML_TAGS.add("<header");
        SAFE_HTML_TAGS.add("<footer");
        SAFE_HTML_TAGS.add("<nav");
        SAFE_HTML_TAGS.add("<section");
        SAFE_HTML_TAGS.add("<article");
        SAFE_HTML_TAGS.add("<aside");
        SAFE_HTML_TAGS.add("<main");
        SAFE_HTML_TAGS.add("<details");
        SAFE_HTML_TAGS.add("<summary");
        SAFE_HTML_TAGS.add("<dialog");
        SAFE_HTML_TAGS.add("<template");
        SAFE_HTML_TAGS.add("<slot");
        SAFE_HTML_TAGS.add("<time");
        SAFE_HTML_TAGS.add("<mark");
        SAFE_HTML_TAGS.add("<small");
        SAFE_HTML_TAGS.add("<del");
        SAFE_HTML_TAGS.add("<ins");
        SAFE_HTML_TAGS.add("<sub");
        SAFE_HTML_TAGS.add("<sup");
        SAFE_HTML_TAGS.add("<figure");
        SAFE_HTML_TAGS.add("<figcaption");
        SAFE_HTML_TAGS.add("<caption");
        SAFE_HTML_TAGS.add("<colgroup");
        SAFE_HTML_TAGS.add("<col");
        SAFE_HTML_TAGS.add("<datalist");
        SAFE_HTML_TAGS.add("<fieldset");
        SAFE_HTML_TAGS.add("<legend");
        SAFE_HTML_TAGS.add("<meter");
        SAFE_HTML_TAGS.add("<progress");
        SAFE_HTML_TAGS.add("<output");
        SAFE_HTML_TAGS.add("<address");
        SAFE_HTML_TAGS.add("<dl");
        SAFE_HTML_TAGS.add("<dt");
        SAFE_HTML_TAGS.add("<dd");
        SAFE_HTML_TAGS.add("<kbd");
        SAFE_HTML_TAGS.add("<samp");
        SAFE_HTML_TAGS.add("<var");
        SAFE_HTML_TAGS.add("<abbr");
        SAFE_HTML_TAGS.add("<cite");
        SAFE_HTML_TAGS.add("<q");
        SAFE_HTML_TAGS.add("<wbr");
        SAFE_HTML_TAGS.add("<bdi");
        SAFE_HTML_TAGS.add("<bdo");
        SAFE_HTML_TAGS.add("<ruby");
        SAFE_HTML_TAGS.add("<rt");
        SAFE_HTML_TAGS.add("<rp");
        SAFE_HTML_TAGS.add("<picture");
        SAFE_HTML_TAGS.add("<noscript");
        SAFE_HTML_TAGS.add("<iframe");  // iframe 本身不危险，危险在于其属性
        SAFE_HTML_TAGS.add("<object");  // object 本身不危险，危险在于其属性
        SAFE_HTML_TAGS.add("<embed");   // embed 本身不危险，危险在于其属性
        SAFE_HTML_TAGS.add("<applet");  // applet 本身不危险，危险在于其属性

        // ===== 危险模式定义 =====
        // 1. 极高危模式 (15分)
        DANGEROUS_PATTERNS.put("constructor.constructor", 25);
        DANGEROUS_PATTERNS.put("eval(", 25);
        DANGEROUS_PATTERNS.put("execscript(", 25);
        DANGEROUS_PATTERNS.put("new function(", 5);
        DANGEROUS_PATTERNS.put("function`", 10);
        DANGEROUS_PATTERNS.put("new function", 5);
        DANGEROUS_PATTERNS.put("reflect.apply", 10);
        DANGEROUS_PATTERNS.put("reflect.construct", 20);
        DANGEROUS_PATTERNS.put("webassembly", 18);
        DANGEROUS_PATTERNS.put("import(", 8);
        DANGEROUS_PATTERNS.put("importscripts", 18);

        // 2. 高危模式 (15-18分)
        DANGEROUS_PATTERNS.put("<script", 18);
        DANGEROUS_PATTERNS.put("</script>", 18);
        DANGEROUS_PATTERNS.put("javascript:", 10);
        DANGEROUS_PATTERNS.put("document.write", 16);
        DANGEROUS_PATTERNS.put("document.writeln", 16);
        DANGEROUS_PATTERNS.put("document.cookie", 16);
        DANGEROUS_PATTERNS.put("<iframe", 10);
        DANGEROUS_PATTERNS.put("__proto__", 18);
        DANGEROUS_PATTERNS.put("prototype", 12);

        // 3. 中危模式 (12-14分)
        DANGEROUS_PATTERNS.put("alert(", 14);
        DANGEROUS_PATTERNS.put("confirm(", 14);
        DANGEROUS_PATTERNS.put("prompt(", 14);
        DANGEROUS_PATTERNS.put("innerhtml", 14);
        DANGEROUS_PATTERNS.put("outerhtml", 14);
        DANGEROUS_PATTERNS.put("location.href", 14);
        DANGEROUS_PATTERNS.put("location.hash.slice", 16);
        DANGEROUS_PATTERNS.put("vbscript:", 16);
        DANGEROUS_PATTERNS.put("serviceworker", 16);
        DANGEROUS_PATTERNS.put("appendchild", 12);
        DANGEROUS_PATTERNS.put("createelement", 14);
        DANGEROUS_PATTERNS.put("document.createelement", 18);
        DANGEROUS_PATTERNS.put("insertbefore", 12);
        DANGEROUS_PATTERNS.put("settimeout", 12);
        DANGEROUS_PATTERNS.put("setinterval", 12);
        DANGEROUS_PATTERNS.put("window.open", 12);
        DANGEROUS_PATTERNS.put("insertadjacenthtml", 14);
        DANGEROUS_PATTERNS.put("insertadjacentelement", 14);



        // 4. 低危模式 (8-10分)
        DANGEROUS_PATTERNS.put("document.", 10);
        DANGEROUS_PATTERNS.put("window.", 10);
        DANGEROUS_PATTERNS.put("location.", 10);
        DANGEROUS_PATTERNS.put("navigator.", 8);
        DANGEROUS_PATTERNS.put("?.", 5);
        DANGEROUS_PATTERNS.put("?.(", 10);
        DANGEROUS_PATTERNS.put("location.hash", 8);

        // 5. 事件处理器 (14-18分)
        DANGEROUS_PATTERNS.put("onload=", 18);
        DANGEROUS_PATTERNS.put("onerror=", 18);
        DANGEROUS_PATTERNS.put("onclick=", 16);
        DANGEROUS_PATTERNS.put("onmouseover=", 16);
        DANGEROUS_PATTERNS.put("onfocus=", 16);
        DANGEROUS_PATTERNS.put("onblur=", 14);
        DANGEROUS_PATTERNS.put("onchange=", 14);
        DANGEROUS_PATTERNS.put("onsubmit=", 14);
        DANGEROUS_PATTERNS.put("onkeydown=", 14);
        DANGEROUS_PATTERNS.put("onkeyup=", 14);
        DANGEROUS_PATTERNS.put("onkeypress=", 14);

        // 6. 属性注入 (6分)
        DANGEROUS_PATTERNS.put("src=", 6);
        DANGEROUS_PATTERNS.put("href=", 6);
        DANGEROUS_PATTERNS.put("action=", 6);
        DANGEROUS_PATTERNS.put("background=", 6);
        DANGEROUS_PATTERNS.put("style=", 6);

        // 7. 编码特征 (3-10分)

        DANGEROUS_PATTERNS.put("atob(", 10);
        DANGEROUS_PATTERNS.put("fromcharcode", 10);
        DANGEROUS_PATTERNS.put("unescape(", 8);
        DANGEROUS_PATTERNS.put("expression(", 10);


        // 8. 伪协议 (10-12分)
        DANGEROUS_PATTERNS.put("livescript:", 5);
        DANGEROUS_PATTERNS.put("mocha:", 5);
        DANGEROUS_PATTERNS.put("blob:", 5);

        // 9. 对象属性绕过 (8-18分)
        DANGEROUS_PATTERNS.put("[o.a+o.b]", 18);
        DANGEROUS_PATTERNS.put("[a+b]", 15);
        DANGEROUS_PATTERNS.put("['ev']", 12);
        DANGEROUS_PATTERNS.put("['al']", 12);
        DANGEROUS_PATTERNS.put("window[", 8);
        DANGEROUS_PATTERNS.put("document[", 8);
        DANGEROUS_PATTERNS.put("this[", 8);

        // 10. 高级绕过特征 (6-15分)
        DANGEROUS_PATTERNS.put("string.fromcharcode", 15);
        DANGEROUS_PATTERNS.put(".constructor", 6);
        DANGEROUS_PATTERNS.put("[\"constructor\"]", 6);
        DANGEROUS_PATTERNS.put("['constructor']", 6);
        DANGEROUS_PATTERNS.put("with(", 6);
        DANGEROUS_PATTERNS.put("top.", 6);
        DANGEROUS_PATTERNS.put("parent.", 6);
        DANGEROUS_PATTERNS.put("self.", 6);
        DANGEROUS_PATTERNS.put("frames[", 8);
        DANGEROUS_PATTERNS.put("contentwindow", 10);
        DANGEROUS_PATTERNS.put("contentdocument", 10);

        // 11. 模板字符串绕过 (8分)
        DANGEROUS_PATTERNS.put("${", 8);
        DANGEROUS_PATTERNS.put("`+", 8);
        DANGEROUS_PATTERNS.put("+`", 8);

        // 12. Symbol绕过 (8-10分)
        DANGEROUS_PATTERNS.put("symbol.for", 10);
        DANGEROUS_PATTERNS.put("symbol.iterator", 8);

        // 13. 异步绕过 (6分)
        DANGEROUS_PATTERNS.put("async function", 3);
        DANGEROUS_PATTERNS.put(".then(", 6);



        // 15. 现代前端框架注入 (5-15分)
        DANGEROUS_PATTERNS.put("v-html", 12);
        DANGEROUS_PATTERNS.put("v-bind:href", 10);
        DANGEROUS_PATTERNS.put(":href", 5);
        DANGEROUS_PATTERNS.put("dangerouslysetinnerhtml", 15);
        DANGEROUS_PATTERNS.put("ng-bind-html", 12);
        DANGEROUS_PATTERNS.put("ng-app", 10);
        DANGEROUS_PATTERNS.put("[innerhtml]", 6);



        // 18. WebRTC和其他API (6-8分)
        DANGEROUS_PATTERNS.put("rtcpeerconnection", 8);
        DANGEROUS_PATTERNS.put("getusermedia", 8);
        DANGEROUS_PATTERNS.put("indexeddb", 6);
        DANGEROUS_PATTERNS.put("websocket", 8);

        // 19. 其他危险操作
        DANGEROUS_PATTERNS.put("localstorage", 6);
        DANGEROUS_PATTERNS.put("fetch", 6);
        DANGEROUS_PATTERNS.put("xmlhttprequest", 8);

        // 20. 高级XSS绕过技术 (8-15分)
        DANGEROUS_PATTERNS.put("data:text/html", 12);
        DANGEROUS_PATTERNS.put("srcdoc=", 10);
        DANGEROUS_PATTERNS.put("formaction=", 8);
        DANGEROUS_PATTERNS.put("poster=", 7);
        DANGEROUS_PATTERNS.put("codebase=", 8);
        DANGEROUS_PATTERNS.put("data=", 5);
        DANGEROUS_PATTERNS.put("manifest=", 7);



        // 24. JavaScript伪协议变体 (10-12分)
        DANGEROUS_PATTERNS.put("jav&#x09;ascript:", 15);
        DANGEROUS_PATTERNS.put("jav&#x0a;ascript:", 15);
        DANGEROUS_PATTERNS.put("jav&#x0d;ascript:", 15);
        DANGEROUS_PATTERNS.put("java\tscript:", 12);
        DANGEROUS_PATTERNS.put("java\nscript:", 12);
        DANGEROUS_PATTERNS.put("java\rscript:", 12);

        // 25. 事件处理器变体 (12-16分)
        DANGEROUS_PATTERNS.put("onabort=", 14);
        DANGEROUS_PATTERNS.put("onanimationend=", 14);
        DANGEROUS_PATTERNS.put("onanimationstart=", 14);
        DANGEROUS_PATTERNS.put("onbeforeunload=", 16);
        DANGEROUS_PATTERNS.put("oncanplay=", 12);
        DANGEROUS_PATTERNS.put("ondrag=", 14);
        DANGEROUS_PATTERNS.put("ondrop=", 14);
        DANGEROUS_PATTERNS.put("oninput=", 14);
        DANGEROUS_PATTERNS.put("oninvalid=", 12);
        DANGEROUS_PATTERNS.put("onpaste=", 14);
        DANGEROUS_PATTERNS.put("onplay=", 12);
        DANGEROUS_PATTERNS.put("onpointerover=", 12);
        DANGEROUS_PATTERNS.put("onreset=", 12);
        DANGEROUS_PATTERNS.put("onresize=", 12);
        DANGEROUS_PATTERNS.put("onscroll=", 12);
        DANGEROUS_PATTERNS.put("onsearch=", 12);
        DANGEROUS_PATTERNS.put("onselect=", 12);
        DANGEROUS_PATTERNS.put("ontoggle=", 12);
        DANGEROUS_PATTERNS.put("ontouchstart=", 14);
        DANGEROUS_PATTERNS.put("ontransitionend=", 12);
        DANGEROUS_PATTERNS.put("onwheel=", 12);

        // 26. HTML5新标签 - 已移至安全标签白名单，不再作为危险模式



        // 30. 危险的全局对象访问 (8-12分)
        DANGEROUS_PATTERNS.put("globalthis", 10);
        DANGEROUS_PATTERNS.put("process.env", 10);
        DANGEROUS_PATTERNS.put("require(", 5);
        DANGEROUS_PATTERNS.put("module.exports", 5);
        DANGEROUS_PATTERNS.put("arguments.callee", 10);
        DANGEROUS_PATTERNS.put("arguments.caller", 10);

        // 31. 字符串拆分特征 (10-15分)
        DANGEROUS_PATTERNS.put(".split('').reverse().join('')", 15);
        DANGEROUS_PATTERNS.put(".charcodeat", 10);
        DANGEROUS_PATTERNS.put(".codepointat", 10);
        DANGEROUS_PATTERNS.put(".concat(", 5);

        // 32. 动态代码执行 (12-15分)
        DANGEROUS_PATTERNS.put("function(", 5);

        DANGEROUS_PATTERNS.put("new function", 5);
        DANGEROUS_PATTERNS.put("generatorfunction", 12);
        DANGEROUS_PATTERNS.put("asyncfunction", 12);
    }

    /**
     ◦ 检查是否是安全的JavaScript表达式

     ◦ 综合判断逻辑：

     ◦ 1. 白名单检查

     ◦ 2. 组合高危模式检测

     ◦ 3. XSS常见绕过方式检测

     ◦ 4. 可疑字符串占比过滤（<30%则认为安全）

     */
    private static boolean isSafeJavaScriptExpression(String lowerInput) {
        // 快速检查：如果不包含 javascript:，直接返回
        if (!lowerInput.contains("javascript:")) {
            return false;
        }

        // 移除空格和换行符进行标准化比较
        String normalized = lowerInput.replaceAll("\\s+", "");

        // 1. 检查是否在白名单中（精确匹配）
        for (String safePattern : SAFE_JS_WHITELIST) {
            String normalizedPattern = safePattern.replaceAll("\\s+", "");
            if (normalized.equals(normalizedPattern)) {
                return true;
            }
        }

        // 2. 检测组合高危模式
        if (hasHighRiskCombination(lowerInput)) {
            return false; // 发现高危组合，不安全
        }

        // 3. 检测XSS常见绕过方式
        if (hasXssBypassPattern(lowerInput)) {
            return false; // 发现绕过模式，不安全
        }

        // 4. 可疑字符串占比过滤
        double suspiciousRatio = calculateSuspiciousRatio(lowerInput);
        if (suspiciousRatio < 0.10) {
            return true; // 可疑字符串占比小于30%，认为安全
        }

        // 默认不安全
        return false;
    }

    /**
     ◦ 检测组合高危模式

     ◦ 包括：iframe+javascript、eval+atob、innerHTML+script等

     */
    private static boolean hasHighRiskCombination(String lowerInput) {
        // iframe + javascript伪协议
        if (lowerInput.contains("iframe") && lowerInput.contains("javascript:")) {
            return true;
        }

        // 动态脚本注入：createElement + script + appendChild
        if (lowerInput.contains("createelement") && lowerInput.contains("script") &&
                lowerInput.contains("appendchild")) {
            return true;
        }

        // 编码执行链：eval + atob
        if (lowerInput.contains("eval") && lowerInput.contains("atob")) {
            return true;
        }

        // innerHTML注入：innerHTML + <script
        if (lowerInput.contains("innerhtml") && lowerInput.contains("<script")) {
            return true;
        }

        // constructor绕过：多次出现constructor
        if (countOccurrences(lowerInput, "constructor") >= 2) {
            return true;
        }

        // SVG注入：<svg + (onload|onerror)
        if (lowerInput.contains("<svg") &&
                (lowerInput.contains("onload") || lowerInput.contains("onerror"))) {
            return true;
        }

        // 数据外带：(document.cookie|localstorage) + (fetch|xmlhttprequest)
        if ((lowerInput.contains("document.cookie") || lowerInput.contains("localstorage")) &&
                (lowerInput.contains("fetch") || lowerInput.contains("xmlhttprequest"))) {
            return true;
        }

        // Base标签劫持：<base + href
        if (lowerInput.contains("<base") && lowerInput.contains("href")) {
            return true;
        }

        return false;
    }

    /**
     ◦ 检测XSS常见绕过方式

     ◦ 包括：字符串拆分、编码绕过、变量拼接等

     */
    private static boolean hasXssBypassPattern(String lowerInput) {
        // 1. 字符串拆分绕过：['ev','al'] 或 [`ev`,`al`]
        if (lowerInput.contains("['") && lowerInput.contains("']") && lowerInput.contains(",")) {
            // 检查是否拆分了危险API
            if (lowerInput.contains("'ev'") || lowerInput.contains("'al'") ||
                    lowerInput.contains("'do'") || lowerInput.contains("'cu'") ||
                    lowerInput.contains("`ev`") || lowerInput.contains("`al`")) {
                return true;
            }
        }

        // 2. 变量拼接访问：window[a+b] 或 document[x+y]
        if ((lowerInput.contains("window[") || lowerInput.contains("document[")) &&
                lowerInput.contains("+")) {
            return true;
        }


        if (lowerInput.contains("\\x") || lowerInput.contains("\\u") ||
                lowerInput.contains("&#") || lowerInput.contains("fromcharcode")) {
            return true;
        }

        // 4. Base64绕过：atob + eval/Function
        if (lowerInput.contains("atob") &&
                (lowerInput.contains("eval") || lowerInput.contains("function"))) {
            return true;
        }

        // 5. 数组解构赋值绕过：[a,b,c]=['xx','yy','zz']
        if (countOccurrences(lowerInput, "]=") >= 2) {
            return true;
        }

        // 6. 模板字符串绕过：${...}
        if (lowerInput.contains("${") &&
                (lowerInput.contains("eval") || lowerInput.contains("alert") ||
                        lowerInput.contains("document") || lowerInput.contains("window"))) {
            return true;
        }

        // 7. 反引号标签模板：alert`1` 或 eval`...`
        if ((lowerInput.contains("alert`") || lowerInput.contains("eval`") ||
                lowerInput.contains("prompt`") || lowerInput.contains("confirm`"))) {
            return true;
        }

        // 8. 注释混淆：<!-- 或 /* 包含危险代码
        if ((lowerInput.contains("<!--") || lowerInput.contains("/*")) &&
                (lowerInput.contains("script") || lowerInput.contains("eval") ||
                        lowerInput.contains("alert"))) {
            return true;
        }

        // 9. 事件处理器 + 危险操作
        String[] events = {"onload=", "onerror=", "onclick=", "onmouseover=", "onfocus="};
        for (String event : events) {
            if (lowerInput.contains(event)) {
                int pos = lowerInput.indexOf(event);
                int endPos = Math.min(pos + 50, lowerInput.length());
                String afterEvent = lowerInput.substring(pos, endPos);
                if (afterEvent.contains("alert") || afterEvent.contains("eval") ||
                        afterEvent.contains("document") || afterEvent.contains("window")) {
                    return true;
                }
            }
        }

        // 10. 多层嵌套访问：a[b][c][d]
        int nestedBracketCount = 0;
        for (int i = 0; i < lowerInput.length() - 1; i++) {
            if (lowerInput.charAt(i) == ']' && lowerInput.charAt(i + 1) == '[') {
                nestedBracketCount++;
            }
        }
        if (nestedBracketCount >= 2) {
            return true;
        }

        return false;
    }

    /**
     ◦ 计算可疑字符串占比

     ◦ 统计所有可疑关键字的总长度占输入字符串长度的比例

     ◦ 使用统一的 DANGEROUS_PATTERNS 数据源

     */
    private static double calculateSuspiciousRatio(String lowerInput) {
        if (lowerInput == null || lowerInput.isEmpty()) {
            return 0.0;
        }

        int totalSuspiciousLength = 0;

        // 使用统一的危险模式列表进行检测
        for (String keyword : DANGEROUS_PATTERNS.keySet()) {
            int pos = 0;
            while ((pos = lowerInput.indexOf(keyword, pos)) != -1) {
                totalSuspiciousLength += keyword.length();
                pos += keyword.length();
            }
        }

        // 计算占比
        return (double) totalSuspiciousLength / lowerInput.length();
    }

    /**
     ◦ 完整的XSS检测方法 - 使用统一的危险模式列表

     ◦ 核心检测逻辑，不包含提取和过滤

     */
    public static Map<String, Object> detectXssCore(String input) {
        Map<String, Object> result = new HashMap<>();

        if (input == null || input.trim().isEmpty()) {
            result.put("isXss", false);
            result.put("riskScore", 0);
            result.put("hasMaliciousPattern", false);
            return result;
        }

        String lowerInput = input.toLowerCase();
        int score = 0;
        boolean hasMaliciousPattern = false;
        List<String> hitPatterns = new ArrayList<>(); // 记录命中的恶意模式

        // 使用统一的危险模式列表进行检测
        for (Map.Entry<String, Integer> entry : DANGEROUS_PATTERNS.entrySet()) {
            String pattern = entry.getKey();
            int weight = entry.getValue();

            // 对于需要区分大小写的模式（如 \x, &#, ${），使用原始输入
            String searchInput = (pattern.contains("\\") || pattern.contains("&#") || pattern.contains("${") )
                    ? input : lowerInput;

            if (searchInput.toLowerCase().contains(pattern)) {
                score += weight;
                hitPatterns.add(pattern); // 记录命中的模式

                // 标记特别危险的模式
                if (weight >= 27 ||
                        pattern.equals("constructor.constructor") ||
                        pattern.equals("<script") ||
                        pattern.equals("document.write") ||

                        pattern.equals("[o.a+o.b]") ||
                        pattern.equals("dangerouslysetinnerhtml")) {
                    hasMaliciousPattern = true;
                }
            }
        }

        // ===== 22. 恶意模式组合检测 =====

        // 【极高危组合 - 40+分】

        // constructor链式绕过
        if (countOccurrences(lowerInput, "constructor") >= 2) {
            score += 10;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] constructor chain bypass");
        }

        // 原型链污染 + 代码执行
        if ((lowerInput.contains("__proto__") || lowerInput.contains("prototype")) &&
                (lowerInput.contains("constructor") || lowerInput.contains("eval"))) {
            score += 45;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] prototype pollution + code execution");
        }

        // 动态脚本注入
        if (lowerInput.contains("createelement") && lowerInput.contains("script") &&
                lowerInput.contains("appendchild")) {
            score += 35;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] dynamic script injection");
        }

        // 【高危组合 - 30-35分】

        // 数据外带
        if ((lowerInput.contains("document.cookie") || lowerInput.contains("localstorage")) &&
                (lowerInput.contains("fetch") || lowerInput.contains("xmlhttprequest") ||
                        lowerInput.contains("location.href") || lowerInput.contains("window.open"))) {
            score += 35;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] data exfiltration");
        }

        // iframe + javascript伪协议
        if (lowerInput.contains("iframe") && lowerInput.contains("javascript:")) {
            score += 30;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] iframe + javascript protocol");
        }

        // 编码执行链
        if (lowerInput.contains("eval") &&
                (lowerInput.contains("atob") || lowerInput.contains("fromcharcode") ||
                        lowerInput.contains("unescape"))) {
            score += 30;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] encoding execution chain");
        }

        // SVG注入
        if (lowerInput.contains("<svg") &&
                (lowerInput.contains("onload") || lowerInput.contains("onerror") ||
                        lowerInput.contains("onanimation"))) {
            score += 30;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] SVG injection");
        }

        // 【中高危组合 - 25-28分】

        // innerHTML注入
        if (lowerInput.contains("innerhtml") &&
                (lowerInput.contains("<script") || lowerInput.contains("<iframe") ||
                        lowerInput.contains("javascript:"))) {
            score += 20;
            hitPatterns.add("[COMBO] innerHTML injection");

        }

        // Base标签劫持
        if (lowerInput.contains("<base") && lowerInput.contains("href")) {
            score += 25;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] base tag hijacking");
        }

        // data URI + script
        if (lowerInput.contains("data:text/html") &&
                (lowerInput.contains("<script") || lowerInput.contains("javascript:"))) {
            score += 30;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] data URI + script");
        }

        // srcdoc注入
        if (lowerInput.contains("srcdoc") &&
                (lowerInput.contains("<script") || lowerInput.contains("onerror") ||
                        lowerInput.contains("onload"))) {
            score += 28;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] srcdoc injection");
        }

        // 【中危组合 - 20-24分】

        // 事件处理器 + 危险函数
        String[] dangerousFuncs = {"alert", "eval", "prompt", "confirm", "atob", "fromcharcode"};
        String[] eventHandlers = {"onload", "onerror", "onclick", "onmouseover", "onfocus",
                "oninput", "onanimationend", "ontoggle"};
        for (String event : eventHandlers) {
            if (lowerInput.contains(event + "=")) {
                for (String func : dangerousFuncs) {
                    if (lowerInput.contains(func)) {
                        score += 20;
                        hasMaliciousPattern = true;
                        hitPatterns.add("[COMBO] event handler + " + func);
                        break;
                    }
                }
            }
        }

        // 字符串拆分 + 拼接执行
        if ((lowerInput.contains(".split") || lowerInput.contains(".reverse") ||
                lowerInput.contains(".join")) &&
                (lowerInput.contains("eval") || lowerInput.contains("function") ||
                        lowerInput.contains("constructor"))) {
            score += 22;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] string split + execution");
        }

// 模板字符串 + 代码执行
// 检测 ${...} 中包含的危险代码执行
        if (input.contains("${")) {
            // 提取 ${...} 中的内容
            int startIdx = 0;
            while ((startIdx = input.indexOf("${", startIdx)) != -1) {
                int endIdx = input.indexOf("}", startIdx);
                if (endIdx != -1) {
                    String templateContent = input.substring(startIdx + 2, endIdx).toLowerCase();

                    // 检查模板内容中的危险模式
                    // 1. 直接的代码执行
                    if (templateContent.contains("eval(") ||
                            templateContent.contains("function(") ||
                            templateContent.contains("new function") ||
                            templateContent.contains("constructor(")) {
                        score += 25;
                        hasMaliciousPattern = true;
                        hitPatterns.add("[COMBO] template string + code execution");
                        break;
                    }

                    // 2. 原型链污染 + 代码执行
                    if ((templateContent.contains("__proto__") ||
                            templateContent.contains("prototype") ||
                            templateContent.contains("constructor")) &&
                            (templateContent.contains("alert") ||
                                    templateContent.contains("eval") ||
                                    templateContent.contains("fetch") ||
                                    templateContent.contains("xmlhttprequest"))) {
                        score += 23;
                        hasMaliciousPattern = true;
                        hitPatterns.add("[COMBO] template string + prototype pollution");
                        break;
                    }

                    // 3. 危险的 API 调用
                    if ((templateContent.contains("document.write") ||
                            templateContent.contains("innerhtml") ||
                            templateContent.contains("outerhtml") ||
                            templateContent.contains("insertadjacenthtml")) &&
                            (templateContent.contains("<") || templateContent.contains(">"))) {
                        score += 22;
                        hasMaliciousPattern = true;
                        break;
                    }

                    // 4. 事件处理器 + 代码执行
                    if ((templateContent.contains("onclick") ||
                            templateContent.contains("onerror") ||
                            templateContent.contains("onload")) &&
                            (templateContent.contains("alert") ||
                                    templateContent.contains("eval") ||
                                    templateContent.contains("fetch"))) {
                        score += 20;
                        hasMaliciousPattern = true;
                        break;
                    }

                    // 5. 简单的危险函数调用
                    if (templateContent.contains("alert(") ||
                            templateContent.contains("confirm(") ||
                            templateContent.contains("prompt(")) {
                        score += 18;
                        hasMaliciousPattern = true;
                        break;
                    }

                    startIdx = endIdx + 1;
                } else {
                    break;
                }
            }
        }

        // 反引号标签模板
        if ((lowerInput.contains("alert`") || lowerInput.contains("eval`") ||
                lowerInput.contains("prompt`") || lowerInput.contains("confirm`"))) {
            score += 20;
            hasMaliciousPattern = true;
        }

        // 【特殊绕过检测 - 15-20分】




        // 空格/换行符混淆
        if ((input.contains("\t") || input.contains("\n") || input.contains("\r")) &&
                (lowerInput.contains("javascript:") || lowerInput.contains("onerror") ||
                        lowerInput.contains("onload"))) {
            score += 20;
        }



        // 变量拼接绕过
        if ((lowerInput.contains("window[") || lowerInput.contains("document[") ||
                lowerInput.contains("this[")) &&
                (lowerInput.contains("+") || lowerInput.contains(".concat"))) {
            score += 18;
            hasMaliciousPattern = true;
        }

        // 数组索引字符串拼接绕过检测
        // 检测类似 ['cre'+'ate'+'Elem'+'ent'] 或 ["b"+"o"+"d"+"y"] 这种模式
        int stringConcatBypassScore = detectStringConcatBypass(input, lowerInput);
        if (stringConcatBypassScore > 0) {
            score += stringConcatBypassScore;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] array index string concatenation bypass");
        }

        // 数组解构赋值绕过 - 基础检测
        if (countOccurrences(lowerInput, "]=") >= 2 &&
                (lowerInput.contains("window") || lowerInput.contains("document") ||
                        lowerInput.contains("eval"))) {
            score += 30;
            hasMaliciousPattern = true;
        }

        // 高级数组解构赋值绕过 - 多层拆分检测
        int advancedDestructuringScore = detectAdvancedDestructuringBypass(input, lowerInput);
        if (advancedDestructuringScore > 0) {
            score += advancedDestructuringScore;
            hasMaliciousPattern = true;
            hitPatterns.add("[COMBO] hi array index string concatenation bypass");
        }

// 【框架特定注入 - 15-20分】

        // Vue.js注入
        if ((lowerInput.contains("v-html") || lowerInput.contains("v-bind")) &&
                (lowerInput.contains("javascript:") || lowerInput.contains("onerror"))) {
            score += 20;
            hasMaliciousPattern = true;
        }

        // React注入
        if (lowerInput.contains("dangerouslysetinnerhtml") &&
                (lowerInput.contains("<script") || lowerInput.contains("onerror"))) {
            score += 20;
            hasMaliciousPattern = true;
        }









        // 【分数调整】根据命中恶意模式的长度比例调整分数
        // 计算所有命中的恶意模式的总长度
        int totalMaliciousLength = 0;
        for (Map.Entry<String, Integer> entry : DANGEROUS_PATTERNS.entrySet()) {
            String pattern = entry.getKey();
            String searchInput = (pattern.contains("\\") || pattern.contains("&#") || pattern.contains("${") )
                    ? input : lowerInput;

            int pos = 0;
            while ((pos = searchInput.indexOf(pattern, pos)) != -1) {
                totalMaliciousLength += pattern.length();
                pos += pattern.length();
            }
        }

        // 计算恶意内容占比
        double maliciousRatio = 0.0;
        if (input.length() > 0) {
            maliciousRatio = (double) totalMaliciousLength / input.length();
        }

        // 【分数调整规则】最多调整 ±15 分
        // 根据恶意内容占比计算调整幅度（-15 到 +15）
        int scoreAdjustment = 0;
        if (maliciousRatio < 0.05) {
            // 恶意内容占比 < 5%，降低 15 分
            scoreAdjustment = -15;
        } else if (maliciousRatio < 0.1) {
            // 恶意内容占比 5-10%，降低 10 分
            scoreAdjustment = -10;
        } else if (maliciousRatio < 0.2) {
            // 恶意内容占比 10-20%，降低 5 分
            scoreAdjustment = -5;
        } else if (maliciousRatio > 0.7) {
            // 恶意内容占比 > 70%，提升 15 分
            scoreAdjustment = 15;
        } else if (maliciousRatio > 0.5) {
            // 恶意内容占比 50-70%，提升 10 分
            scoreAdjustment = 10;
        } else if (maliciousRatio > 0.3) {
            // 恶意内容占比 30-50%，提升 5 分
            scoreAdjustment = 5;
        }

        // 应用分数调整（确保分数不为负）
        score = Math.max(0, score + scoreAdjustment);

        result.put("isXss", score > XSS_DETECTION_THRESHOLD || hasMaliciousPattern);
        result.put("riskScore", score);
        result.put("hasMaliciousPattern", hasMaliciousPattern);
        result.put("maliciousRatio", String.format("%.2f%%", maliciousRatio * 100));
        result.put("totalMaliciousLength", totalMaliciousLength);
        result.put("inputLength", input.length());
        result.put("hitPatterns", hitPatterns); // 返回命中的恶意模式列表

        return result;
    }

    /**
     ◦ 计算字符串出现次数

     */
    private static int countOccurrences(String text, String pattern) {
        int count = 0;
        int pos = 0;
        while ((pos = text.indexOf(pattern, pos)) != -1) {
            count++;
            pos += pattern.length();
        }
        return count;
    }

    /**
     ◦ 检测数组索引字符串拼接绕过

     ◦ 检测类似以下模式的绕过：

     *
     ◦ 模式1 - 加号拼接：

     ◦ c['cre'+'ate'+'Elem'+'ent']

     ◦ c['b'+'o'+'d'+'y']

     ◦ d['s'+'rc']

     *
     ◦ 模式2 - 逗号分隔数组：

     ◦ c['cre','ate','Elem','ent']

     ◦ c['b','o','d','y']

     ◦ d['s','rc']

     *
     ◦ 特征：

     ◦ 1. 使用方括号访问属性 [...]

     ◦ 2. 方括号内包含字符串拼接 '...'+'...' 或数组 '...','...'

     ◦ 3. 拼接的字符串组合后是敏感API名称

     ◦ 4. 可能使用单引号、双引号或反引号

     *
     ◦ 使用字符串遍历方式实现，避免复杂正则

     */
    private static int detectStringConcatBypass(String input, String lowerInput) {
        int suspicionScore = 0;

        // 定义敏感的API名称和属性
        String[] sensitiveAPIs = {
                "createelement", "appendchild", "insertbefore", "innerhtml", "outerhtml",
                "body", "head", "document", "write", "writeln", "eval", "constructor",
                "src", "href", "onclick", "onerror", "onload", "onmouseover", "onfocus",
                "alert", "prompt", "confirm", "location", "cookie", "localstorage",
                "settimeout", "setinterval", "function", "script", "iframe"
        };

        int matchCount = 0;
        int sensitiveAPIMatchCount = 0;

        // 遍历字符串，查找方括号内的字符串拼接模式
        int len = input.length();
        for (int i = 0; i < len; i++) {
            // 找到左方括号
            if (input.charAt(i) == '[') {
                // 查找对应的右方括号
                int bracketEnd = findMatchingBracket(input, i);
                if (bracketEnd == -1) {
                    continue; // 没有找到匹配的右方括号
                }

                // 提取方括号内的内容
                String bracketContent = input.substring(i + 1, bracketEnd);

                // 检查是否包含字符串拼接模式
                if (isStringConcatenation(bracketContent)) {
                    matchCount++;

                    // 提取拼接后的字符串
                    String concatenated = extractConcatenatedString(bracketContent);

                    if (concatenated != null && !concatenated.isEmpty()) {
                        String concatenatedLower = concatenated.toLowerCase();

                        // 检查是否是敏感API
                        boolean isSensitive = false;
                        for (String api : sensitiveAPIs) {
                            if (concatenatedLower.equals(api) || concatenatedLower.contains(api)) {
                                isSensitive = true;
                                sensitiveAPIMatchCount++;
                                suspicionScore += 30; // 找到敏感API的拼接，高危
                                break;
                            }
                        }

                        // 即使不是已知的敏感API，只要使用了这种拼接方式也加分
                        if (!isSensitive) {
                            suspicionScore += 5; // 使用字符串拼接访问属性，中危
                        }

                        // 检查是否后面跟着函数调用 ](
                        if (bracketEnd + 1 < len && input.charAt(bracketEnd + 1) == '(') {
                            suspicionScore += 20; // 拼接后立即调用，增加可疑度
                        }
                    }
                }

                // 跳过已处理的方括号内容
                i = bracketEnd;
            }
        }

        // 检测多次使用这种绕过技术
        if (matchCount >= 3) {
            suspicionScore += 30; // 多次使用，明显的绕过意图
        } else if (matchCount >= 2) {
            suspicionScore += 10;
        }

        // 检测是否在script标签内或与script相关
        if (matchCount > 0 && (lowerInput.contains("<script") ||lowerInput.contains("<iframe") || lowerInput.contains("</script"))) {
            suspicionScore += 15; // 在script标签中使用，高度可疑
        }

        return suspicionScore;
    }

    /**
     ◦ 查找匹配的右方括号位置

     */
    private static int findMatchingBracket(String input, int startPos) {
        int depth = 1;
        for (int i = startPos + 1; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1; // 没有找到匹配的右方括号
    }

    /**
     ◦ 检查字符串是否包含字符串拼接模式

     ◦ 检测模式：

     ◦ 1. '...'+'...' 或 "..."+"..." 或 `...`+`...` (加号拼接)

     ◦ 2. '...','...' 或 "...","..." 或 `...`,`...` (逗号分隔数组)

     *
     ◦ 注意：需要排除正常的JSON结构，如 {"name":"value","key":"value"}

     */
    private static boolean isStringConcatenation(String content) {
        // 【关键过滤】只要包含冒号就排除，因为是JSON键值对
        // 攻击代码不会有冒号：['cre'+'ate'] 或 ['cre','ate']
        // 正常JSON有冒号："name":"value"
        if (content.contains(":")) {
            return false;
        }

        // 检查是否包含引号（单引号、双引号或反引号）
        boolean hasQuote = content.contains("'") || content.contains("\"") || content.contains("`");
        if (!hasQuote) {
            return false;
        }

        // 简单检查：至少有2个字符串字面量（通过引号对数量判断）
        int singleQuoteCount = countCharSimple(content, '\'');
        int doubleQuoteCount = countCharSimple(content, '"');
        int backtickCount = countCharSimple(content, '`');

        // 至少需要4个引号（2对）才能形成字符串拼接或数组
        boolean hasMultipleStrings = (singleQuoteCount >= 4) || (doubleQuoteCount >= 4) || (backtickCount >= 4);

        if (!hasMultipleStrings) {
            return false;
        }

        // 必须包含加号或逗号作为分隔符
        boolean hasSeparator = content.contains("+") || content.contains(",");

        if (!hasSeparator) {
            return false;
        }

        // 【额外过滤】如果只有逗号（没有加号），检查是否是短字符串拼接
        // 真正的攻击：['cre','ate','Elem','ent'] - 多个短字符串
        // 正常数据：["储存方式","常温"] - 完整的词语
        if (!content.contains("+") && content.contains(",")) {
            // 提取所有字符串，检查是否都是短字符串（<=4个字符）
            int shortStringCount = countShortStrings(content);
            // 如果有3个以上的短字符串，才认为是拼接攻击
            return shortStringCount >= 3;
        }

        return true;
    }

    /**
     ◦ 统计短字符串的数量（<=4个字符的字符串，且必须包含字母）

     ◦ 用于区分真正的拼接攻击和正常数据

     *
     ◦ 攻击代码：['cre','ate','Elem','ent'] - 都是字母，统计

     ◦ 正常数据：["123","456"] - 纯数字，不统计

     ◦ 正常数据：["",""] - 空字符串，不统计

     */
    public static int countShortStrings(String content) {
        int count = 0;
        int i = 0;
        int len = content.length();

        while (i < len) {
            char c = content.charAt(i);

            // 遇到引号，提取字符串
            if (c == '\'' || c == '"' || c == '`') {
                char quoteChar = c;
                i++; // 跳过开始引号
                int stringStart = i;

                // 找到结束引号，同时提取字符串内容
                StringBuilder stringContent = new StringBuilder();
                while (i < len && content.charAt(i) != quoteChar) {
                    if (content.charAt(i) == '\\' && i + 1 < len) {
                        i++; // 跳过转义符
                    }
                    stringContent.append(content.charAt(i));
                    i++;
                }

                // 计算字符串长度并检查是否包含字母
                int stringLength = i - stringStart;
                if (stringLength > 0 && stringLength <= 8) {
                    // 只统计包含字母的短字符串
                    if (containsLetter(stringContent.toString())) {
                        count++;
                    }
                }

                if (i < len) {
                    i++; // 跳过结束引号
                }
            } else {
                i++;
            }
        }

        return count;
    }

    /**
     ◦ 检查字符串是否包含字母

     */
    private static boolean containsLetter(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        for (int i = 0; i < str.length(); i++) {
            if (Character.isLetter(str.charAt(i))) {
                return true;
            }
        }

        return false;
    }

    /**
     ◦ 跳过空白字符，返回下一个非空白字符的位置

     ◦ 用于检测 ]( 或 ][ 模式时忽略中间的空白

     *
     ◦ @param str 输入字符串

     ◦ @param startPos 开始位置

     ◦ @return 下一个非空白字符的位置，如果到达字符串末尾则返回字符串长度

     */
    private static int skipWhitespace(String str, int startPos) {
        int pos = startPos;
        while (pos < str.length() && Character.isWhitespace(str.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    /**
     ◦ 查找匹配的左中括号位置（向前查找）

     ◦ 用于检测 ]( 模式时，确认前面的中括号内容

     *
     ◦ @param str 输入字符串

     ◦ @param closeBracketPos 右中括号的位置

     ◦ @return 匹配的左中括号位置，如果没找到返回-1

     */
    private static int findMatchingOpenBracket(String str, int closeBracketPos) {
        int depth = 1;
        for (int i = closeBracketPos - 1; i >= 0; i--) {
            char c = str.charAt(i);
            if (c == ']') {
                depth++;
            } else if (c == '[') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1; // 没有找到匹配的左中括号
    }

    /**
     ◦ 检查圆括号中是否有内容（不是空括号）

     ◦ 用于 ]( 模式检测，确保不是 ]()

     *
     ◦ @param str 输入字符串

     ◦ @param openParenPos 左圆括号的位置

     ◦ @return 如果圆括号中有内容返回true，否则返回false

     */
    private static boolean hasContentInParentheses(String str, int openParenPos) {
        if (openParenPos >= str.length() || str.charAt(openParenPos) != '(') {
            return false;
        }

        // 查找匹配的右圆括号
        int depth = 1;
        int pos = openParenPos + 1;

        while (pos < str.length() && depth > 0) {
            char c = str.charAt(pos);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    // 找到匹配的右括号，检查中间是否有非空白内容
                    String content = str.substring(openParenPos + 1, pos).trim();
                    return !content.isEmpty();
                }
            }
            pos++;
        }

        return false; // 没有找到匹配的右括号
    }

    /**
     ◦ 检查中括号中是否包含字符串拼接模式

     ◦ 用于 ][ 模式检测，确保是字符串拼接而不是普通数组访问

     *
     ◦ 检查条件：

     ◦ 1. 必须包含 , 或 +（拼接符号）

     ◦ 2. 必须包含引号 ' 或 " 或 `（字符串字面量）

     ◦ 3. 字符串内容只能是字母（排除纯数字、纯符号）

     *
     ◦ @param str 输入字符串

     ◦ @param openBracketPos 左中括号的位置

     ◦ @return 如果符合字符串拼接模式返回true，否则返回false

     */
    private static boolean hasConcatInBrackets(String str, int openBracketPos) {
        if (openBracketPos >= str.length() || str.charAt(openBracketPos) != '[') {
            return false;
        }

        // 查找匹配的右中括号
        int depth = 1;
        int pos = openBracketPos + 1;

        while (pos < str.length() && depth > 0) {
            char c = str.charAt(pos);
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
                if (depth == 0) {
                    // 找到匹配的右括号，检查内容
                    String content = str.substring(openBracketPos + 1, pos);

                    // 条件1：必须包含 , 或 +
                    boolean hasConcatOperator = content.contains(",") || content.contains("+");
                    if (!hasConcatOperator) {
                        return false;
                    }

                    // 条件2：必须包含引号（字符串字面量）
                    boolean hasQuote = content.contains("'") || content.contains("\"") || content.contains("`");
                    if (!hasQuote) {
                        return false;
                    }

                    // 条件3：提取字符串内容，检查是否只包含字母
                    return hasLetterOnlyStrings(content);
                }
            }
            pos++;
        }

        return false; // 没有找到匹配的右括号
    }

    /**
     ◦ 检查字符串中的字符串字面量是否只包含字母

     ◦ 用于区分攻击代码和正常数据

     *
     ◦ 攻击代码：['cre','ate'] - 只包含字母

     ◦ 正常数据：['123','456'] - 包含数字，不检测

     *
     ◦ @param content 中括号内的内容

     ◦ @return 如果至少有一个字符串只包含字母返回true

     */
    private static boolean hasLetterOnlyStrings(String content) {
        int i = 0;
        int len = content.length();
        int letterOnlyStringCount = 0;

        while (i < len) {
            char c = content.charAt(i);

            // 遇到引号，提取字符串
            if (c == '\'' || c == '"' || c == '`') {
                char quoteChar = c;
                i++; // 跳过开始引号
                StringBuilder stringContent = new StringBuilder();

                // 提取引号内的内容
                while (i < len && content.charAt(i) != quoteChar) {
                    if (content.charAt(i) == '\\' && i + 1 < len) {
                        i++; // 跳过转义符
                    }
                    stringContent.append(content.charAt(i));
                    i++;
                }

                // 检查字符串内容是否只包含字母
                String str = stringContent.toString();
                if (!str.isEmpty() && isLetterOnly(str)) {
                    letterOnlyStringCount++;
                }

                if (i < len) {
                    i++; // 跳过结束引号
                }
            } else {
                i++;
            }
        }

        // 至少有一个只包含字母的字符串
        return letterOnlyStringCount > 0;
    }

    /**
     ◦ 检查字符串是否只包含字母

     *
     ◦ @param str 输入字符串

     ◦ @return 如果只包含字母返回true，否则返回false

     */
    private static boolean isLetterOnly(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        for (int i = 0; i < str.length(); i++) {
            if (!Character.isLetter(str.charAt(i))) {
                return false;
            }
        }

        return true;
    }

    /**
     ◦ 检查字符串是否包含中文字符

     ◦ 用于排除 Markdown 链接等包含中文的正常文本

     *
     ◦ 中文字符范围：

     ◦ - CJK统一汉字：\u4E00-\u9FFF

     ◦ - CJK扩展A：\u3400-\u4DBF

     ◦ - CJK兼容汉字：\uF900-\uFAFF

     *
     ◦ @param str 输入字符串

     ◦ @return 如果包含中文字符返回true，否则返回false

     */
    private static boolean containsChinese(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            // 检查是否在中文字符范围内
            if ((c >= 0x4E00 && c <= 0x9FFF) ||   // CJK统一汉字
                    (c >= 0x3400 && c <= 0x4DBF) ||   // CJK扩展A
                    (c >= 0xF900 && c <= 0xFAFF)) {   // CJK兼容汉字
                return true;
            }
        }

        return false;
    }

    /**
     ◦ 统计字符出现次数（简单版本，统计所有出现）

     */
    private static int countCharSimple(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }

    /**
     ◦ 提取拼接后的字符串内容

     ◦ 支持两种模式：

     ◦ 1. 从 'cre'+'ate'+'Elem'+'ent' 提取出 createelement

     ◦ 2. 从 'cre','ate','Elem','ent' 提取出 createelement

     */
    private static String extractConcatenatedString(String content) {
        StringBuilder result = new StringBuilder();

        int i = 0;
        int len = content.length();

        while (i < len) {
            char c = content.charAt(i);

            // 遇到引号，提取字符串内容
            if (c == '\'' || c == '"' || c == '`') {
                char quoteChar = c;
                i++; // 跳过开始引号

                // 提取引号内的内容
                while (i < len && content.charAt(i) != quoteChar) {
                    // 处理转义字符
                    if (content.charAt(i) == '\\' && i + 1 < len) {
                        i++; // 跳过转义符
                    }
                    result.append(content.charAt(i));
                    i++;
                }

                if (i < len) {
                    i++; // 跳过结束引号
                }
            } else if (c == '+' || c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                // 跳过加号、逗号和空白字符
                i++;
            } else {
                // 其他字符直接跳过（可能是变量名等）
                i++;
            }
        }

        return result.toString();
    }

    /**
     ◦ 检测链式方括号属性访问后跟函数调用的模式

     ◦ 检测类似以下模式的绕过：

     ◦ ['b'+'o'+'d'+'y']['app'+'e'+'ndC'+'hi'+'ld'](d)

     ◦ c['cre'+'ate']('script')

     ◦ [`location`]()

     ◦ document['cre'+'ate'+'Elem'+'ent']('script')

     *
     ◦ 特征：

     ◦ 1. 方括号属性访问 [...]

     ◦ 2. 后面跟着函数调用 (...)

     ◦ 3. 可能是链式调用 [...][...](...)

     ◦ 4. 方括号内可能包含字符串拼接

     */
    private static int detectAdvancedDestructuringBypass(String input, String lowerInput) {
        int suspicionScore = 0;

        // 遍历字符串，查找 ]( 模式（方括号后跟函数调用）
        int len = input.length();
        int bracketCallCount = 0; // 统计 ]( 出现次数
        int chainedBracketCount = 0; // 统计 ][ 出现次数（链式调用）

        for (int i = 0; i < len; i++) {
            if (input.charAt(i) == ']') {
                // 找到右方括号后，跳过空白字符
                int nextNonWhitespace = skipWhitespace(input, i + 1);

                if (nextNonWhitespace < len) {
                    char nextChar = input.charAt(nextNonWhitespace);

                    // 检测 ]( 模式：方括号后跟函数调用（忽略中间的空白）
                    // 要求1：圆括号中必须有字符（不能是空括号）
                    // 要求2：前面的中括号内必须包含引号（字符串字面量）
                    // 要求3：中括号内不能包含中文字符
                    if (nextChar == '(') {
                        // 查找前面匹配的左中括号
                        int openBracketPos = findMatchingOpenBracket(input, i);
                        if (openBracketPos != -1) {
                            String bracketContent = input.substring(openBracketPos + 1, i);
                            // 检查中括号内是否包含引号
                            boolean hasQuote = bracketContent.contains("'") ||
                                    bracketContent.contains("\"") ||
                                    bracketContent.contains("`");

                            // 检查中括号内是否包含中文字符
                            boolean hasChinese = containsChinese(bracketContent);

                            if (hasQuote && !hasChinese && hasContentInParentheses(input, nextNonWhitespace)) {
                                bracketCallCount++;
                                suspicionScore += 25; // 方括号后跟函数调用，高危
                            }
                        }
                    }

                    // 检测 ][ 模式：链式方括号访问（忽略中间的空白）
                    // 要求：中括号中必须包含 , 或 +（表示字符串拼接）
                    if (nextChar == '[') {
                        if (hasConcatInBrackets(input, nextNonWhitespace)) {
                            chainedBracketCount++;
                            suspicionScore += 15; // 链式方括号访问，中危
                        }
                    }
                }
            }
        }

        // 如果没有检测到 ]( 或 ][ 模式，返回0
        if (bracketCallCount == 0 && chainedBracketCount == 0) {
            return 0;
        }

        // 额外加分：多次使用这种模式
        if (bracketCallCount >= 2) {
            suspicionScore += 20; // 多次方括号函数调用
        }

        if (chainedBracketCount >= 2) {
            suspicionScore += 15; // 多次链式访问
        }

        // 检测链式调用后跟函数调用：][...](...)
        // 例如：['body']['appendChild'](d)
        if (chainedBracketCount > 0 && bracketCallCount > 0) {
            suspicionScore += 25; // 链式访问 + 函数调用，极高危
        }

        // 检测是否在script或iframe标签中
        if (bracketCallCount > 0 || chainedBracketCount > 0) {
            if (lowerInput.contains("<script") || lowerInput.contains("<iframe")) {
                suspicionScore += 15;
            }
        }

        // 检测是否包含敏感的对象或方法名
        String[] sensitiveKeywords = {
                "document", "window", "location", "eval", "constructor",
                "createelement", "appendchild", "innerhtml", "body", "head",
                "alert", "prompt", "confirm", "settimeout", "setinterval"
        };

        int sensitiveCount = 0;
        for (String keyword : sensitiveKeywords) {
            if (lowerInput.contains(keyword)) {
                sensitiveCount++;
            }
        }

        // 如果包含多个敏感关键字，增加分数
        if (sensitiveCount >= 3) {
            suspicionScore += 20;
        } else if (sensitiveCount >= 2) {
            suspicionScore += 10;
        }

        // 返回总分，设置上限
        return Math.min(suspicionScore, 100);
    }

    /**
     ◦ 检测API名称是否被拆分成字符串数组 - 增强版

     ◦ 支持单引号、双引号和反引号

     */
    private static boolean containsSplitAPIName(String input, String apiName) {
        // 检测是否包含API名称的拆分片段
        // 例如: document -> ['docu','ment'] 或 [`docu`,`ment`] 或 ["docu","ment"]
        if (apiName.length() < 3) return false;

        // 尝试不同的拆分位置
        for (int splitPos = 2; splitPos < apiName.length() - 1; splitPos++) {
            String part1 = apiName.substring(0, splitPos);
            String part2 = apiName.substring(splitPos);

            // 检测各种引号组合的模式
            String[] patterns = {
                    "['" + part1 + "','" + part2 + "']",      // 单引号
                    "[\"" + part1 + "\",\"" + part2 + "\"]",  // 双引号
                    "[`" + part1 + "`,`" + part2 + "`]",      // 反引号
                    "'" + part1 + "','" + part2 + "'",        // 无方括号单引号
                    "\"" + part1 + "\",\"" + part2 + "\"",    // 无方括号双引号
                    "`" + part1 + "`,`" + part2 + "`"         // 无方括号反引号
            };

            for (String pattern : patterns) {
                if (input.toLowerCase().contains(pattern.toLowerCase())) {
                    return true;
                }
            }
        }

        // 检测更细粒度的拆分（每个字符）
        // 例如: ['d','o','c','u','m','e','n','t'] 或 [`d`,`o`,`c`,`u`,`m`,`e`,`n`,`t`]
        if (apiName.length() >= 4) {
            // 单引号版本
            StringBuilder charArrayPattern1 = new StringBuilder();
            // 双引号版本
            StringBuilder charArrayPattern2 = new StringBuilder();
            // 反引号版本
            StringBuilder charArrayPattern3 = new StringBuilder();

            for (int i = 0; i < apiName.length(); i++) {
                if (i > 0) {
                    charArrayPattern1.append(",");
                    charArrayPattern2.append(",");
                    charArrayPattern3.append(",");
                }
                charArrayPattern1.append("'").append(apiName.charAt(i)).append("'");
                charArrayPattern2.append("\"").append(apiName.charAt(i)).append("\"");
                charArrayPattern3.append("`").append(apiName.charAt(i)).append("`");
            }

            if (input.toLowerCase().contains(charArrayPattern1.toString().toLowerCase()) ||
                    input.toLowerCase().contains(charArrayPattern2.toString().toLowerCase()) ||
                    input.toLowerCase().contains(charArrayPattern3.toString().toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    // =========================================================================
    // 业务处理方法
    // =========================================================================


    /**
     ◦ 检测请求体中的XSS

     *
     ◦ @param requestBody 请求体内容

     ◦ @param threshold 检测阈值

     ◦ @return XSS检测结果

     */
    private static Map<String, Object> detectXssInRequestBody(String requestBody, int threshold) {
        if (requestBody == null || requestBody.trim().isEmpty()) {
            return createSafeResult(threshold);
        }
        return detectXss(requestBody, threshold);
    }

    /**
     ◦ 检测URL参数中的XSS

     ◦ 提取URL中?后的参数部分进行检测

     *
     ◦ @param url 完整URL

     ◦ @param threshold 检测阈值

     ◦ @return XSS检测结果

     */
    private static Map<String, Object> detectXssInUrl(String url, int threshold) {
        if (url == null || url.trim().isEmpty()) {
            return createSafeResult(threshold);
        }

        // 提取URL中?后的参数部分
        String queryString = extractQueryString(url);
        if (queryString == null || queryString.trim().isEmpty()) {
            return createSafeResult(threshold);
        }

        // 对参数部分进行XSS检测
        return detectXss(queryString, threshold);
    }

    /**
     ◦ 检测响应体中的XSS

     *
     ◦ @param responseBody 响应体内容

     ◦ @param threshold 检测阈值

     ◦ @return XSS检测结果

     */
    private static Map<String, Object> detectXssInResponseBody(String responseBody, int threshold) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return createSafeResult(threshold);
        }
        return detectXss(responseBody, threshold);
    }

    /**
     ◦ 从URL中提取查询参数字符串（?后的部分）

     *
     ◦ @param url 完整URL

     ◦ @return 查询参数字符串，如果没有则返回null

     */
    private static String extractQueryString(String url) {
        if (url == null || url.trim().isEmpty()) {
            return null;
        }

        // 查找?的位置
        int questionMarkIndex = url.indexOf('?');
        if (questionMarkIndex == -1 || questionMarkIndex == url.length() - 1) {
            return null; // 没有?或?在末尾
        }

        // 提取?后的部分
        String queryString = url.substring(questionMarkIndex + 1);


        return queryString.trim().isEmpty() ? null : queryString;
    }

    // =========================================================================
    // process 入口方法 — 火焰图中 com/example/demo/xss.process 的实现
    // =========================================================================

    /**
     * 综合 XSS 检测入口 — 对 URL、请求体、响应体分别进行检测。
     *
     * 对应火焰图调用链:
     *   CanvasMergeFunction.processCode
     *     → xss.process (W=16464, 占总采样 31.4%)
     *       → xss.detectXssInRequestBody (W=1632)
     *         → xss.detectXss → xss.extract → xss.canonicalizeWithCount
     *           → xss.decodeHtmlEntity / xss.decodeUnicode / xss.decodeUrl
     *         → xss.detectXssInExtractedData → xss.detectXssCore
     *         → xss.createSafeResult
     *       → xss.detectXssInResponseBody (W=14473, 最大热点)
     *         → xss.detectXss → xss.extract
     *           → xss.parseJsonWhole → xss.extractJsonValues
     *           → xss.parseJsonStream → xss.handleTruncatedJson
     *             → xss.extractWithRegex → xss.extractQuotedStrings
     *             → xss.tryParseFixed → xss.countChar
     *           → xss.parseFormDataStream
     *           → xss.canonicalizeWithCount
     *             → xss.decodeHtmlEntity / xss.decodeUrl / xss.decodeUnicode
     *             → xss.detectMiddleControlChars
     *           → xss.repairJsonClosing → xss.repairMissingQuote
     *         → xss.detectXssInExtractedData → xss.detectXssCore
     *       → xss.detectXssInUrl
     *       → xss.filterXssRisk
     *
     * @param parseResult 解析后的数据记录
     * @param threshold   检测阈值
     * @return XssResult 包含三部分检测结论
     */
    public static XssResult process(ParseResult parseResult, int threshold) {
        XssResult xssResult = new XssResult();
        xssResult.setParseResult(parseResult);

        int maxScore = 0;
        boolean detected = false;

        // 1. 检测请求体中的 XSS (火焰图 W=1632)
        Map<String, Object> reqResult = detectXssInRequestBody(
                parseResult.getRequestBody(), threshold);
        xssResult.setRequestBodyResult(reqResult);
        if (reqResult != null) {
            Object isXss = reqResult.get("isXss");
            if (Boolean.TRUE.equals(isXss)) {
                detected = true;
            }
            Object score = reqResult.get("score");
            if (score instanceof Number) {
                maxScore = Math.max(maxScore, ((Number) score).intValue());
            }
        }

        // 2. 检测响应体中的 XSS (火焰图 W=14473, 最大热点)
        Map<String, Object> respResult = detectXssInResponseBody(
                parseResult.getResponseBody(), threshold);
        xssResult.setResponseBodyResult(respResult);
        if (respResult != null) {
            Object isXss = respResult.get("isXss");
            if (Boolean.TRUE.equals(isXss)) {
                detected = true;
            }
            Object score = respResult.get("score");
            if (score instanceof Number) {
                maxScore = Math.max(maxScore, ((Number) score).intValue());
            }
        }

        // 3. 检测 URL 中的 XSS
        Map<String, Object> urlResult = detectXssInUrl(
                parseResult.getUrl(), threshold);
        xssResult.setUrlResult(urlResult);
        if (urlResult != null) {
            Object isXss = urlResult.get("isXss");
            if (Boolean.TRUE.equals(isXss)) {
                detected = true;
            }
            Object score = urlResult.get("score");
            if (score instanceof Number) {
                maxScore = Math.max(maxScore, ((Number) score).intValue());
            }
        }

        xssResult.setXssDetected(detected);
        xssResult.setMaxScore(maxScore);

        return xssResult;
    }

}
