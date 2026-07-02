package com.traffic.wecross.crossverification.dto;

import java.util.List;

public class PageResult<T> {
    public List<T> records;
    public int page;
    public int size;
    public long total;
    public int totalPages;

    public static <T> PageResult<T> of(List<T> records, int page, int size, long total) {
        PageResult<T> result = new PageResult<>();
        result.records = records;
        result.page = page;
        result.size = size;
        result.total = total;
        result.totalPages = size <= 0 ? 0 : (int) Math.ceil((double) total / size);
        return result;
    }
}
