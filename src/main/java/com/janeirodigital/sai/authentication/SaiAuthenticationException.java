package com.janeirodigital.sai.authentication;

/**
 * General exception used to represent issues with authentication processing
 */
public class SaiAuthenticationException extends Exception {
    public SaiAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
    public SaiAuthenticationException(String message) {
        super(message);
    }
}
