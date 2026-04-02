package com.example.cpu.model;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ObjectMap implements Serializable {
    private static final long serialVersionUID = 1L;

    private Map<String, Object> data = new HashMap<>();

    public ObjectMap() {}

    public void put(String key, Object value) {
        data.put(key, value);
    }

    public Object get(String key) {
        return data.get(key);
    }

    public Map<String, Object> getData() {
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "ObjectMap{" +
                "data=" + data +
                '}';
    }
}