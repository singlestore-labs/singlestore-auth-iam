package com.singlestore.s2iam;

@FunctionalInterface
public interface Logger {
    void logf(String format, Object... args);

    Logger STDOUT = (fmt, args) -> System.out.printf(fmt + "%n", args);
}
