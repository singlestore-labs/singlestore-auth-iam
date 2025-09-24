package com.singlestore.s2iam.exceptions;

public class S2IAMException extends Exception {
    public S2IAMException(String message) { super(message); }
    public S2IAMException(String message, Throwable cause) { super(message, cause); }
}
