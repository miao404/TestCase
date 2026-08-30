package com.example.demo.util;

import com.example.demo.record.ParseResult;

import java.io.Serializable;

/**
 * 时间工具类。
 * 对应火焰图中:
 *   com/meituan/rc/zeus/nearline/flink/util/TimeUtil.genEventTime
 *   com/meituan/rc/zeus/nearline/flink/util/TimeUtil.getEventTime
 */
public class TimeUtil implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 生成事件时间。
     * 对应火焰图: TimeUtil.genEventTime
     */
    public static long genEventTime(ParseResult result) {
        if (result.getEventTime() > 0) {
            return result.getEventTime();
        }
        return System.currentTimeMillis();
    }

    /**
     * 获取事件时间。
     * 对应火焰图: TimeUtil.getEventTime
     */
    public static long getEventTime(ParseResult result) {
        return result.getEventTime();
    }
}
