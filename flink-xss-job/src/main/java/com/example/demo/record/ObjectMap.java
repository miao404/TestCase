package com.example.demo.record;

import java.io.Serializable;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * 扩展的有序 Map，用于承载日志字段。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/record/ObjectMap
 */
public class ObjectMap extends LinkedHashMap<String, Object> implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 临时变量前缀 */
    private static final String TMP_PREFIX = "__tmp_";

    public ObjectMap() {
        super();
    }

    public ObjectMap(int initialCapacity) {
        super(initialCapacity);
    }

    public ObjectMap(Map<? extends String, ?> m) {
        super(m);
    }

    /**
     * 过滤字段并构建新的 ObjectMap
     * 对应火焰图: ObjectMap.filterFieldAndBuildObjectMap
     */
    public static ObjectMap filterFieldAndBuildObjectMap(Map<String, Object> source, Set<String> fields) {
        if (source == null || fields == null) {
            return new ObjectMap();
        }
        ObjectMap result = new ObjectMap(fields.size());
        for (String field : fields) {
            if (source.containsKey(field)) {
                result.put(field, source.get(field));
            }
        }
        return result;
    }

    /**
     * 过滤临时变量
     * 对应火焰图: ObjectMap.filterVariables
     */
    public void filterVariables() {
        Predicate<String> isTmp = key -> key != null && key.startsWith(TMP_PREFIX);
        Set<String> keysToRemove = this.keySet().stream()
                .filter(isTmp)
                .collect(Collectors.toSet());
        keysToRemove.forEach(this::remove);
    }
}
