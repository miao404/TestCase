package com.example.cpu.model;

import java.io.Serializable;

public class ParseResult implements Serializable {
    private static final long serialVersionUID = 1L;

    private String rawData;
    private String timestamp;
    private String source;

    public ParseResult() {}

    public ParseResult(String rawData, String timestamp, String source) {
        this.rawData = rawData;
        this.timestamp = timestamp;
        this.source = source;
    }

    public String getRawData() {
        return rawData;
    }

    public void setRawData(String rawData) {
        this.rawData = rawData;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    @Override
    public String toString() {
        return "ParseResult{" +
                "rawData='" + rawData + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", source='" + source + '\'' +
                '}';
    }
}