package com.janeirodigital.sai.authentication;

import lombok.Getter;

import java.io.Serializable;
import java.util.Objects;

/**
 * General representation of a RefreshToken.
 */
@Getter
public class RefreshToken implements Serializable {

    protected final String value;

    /**
     * Construct a new RefreshToken
     * @param value Value of the token itself
     */
    protected RefreshToken(String value) {
        Objects.requireNonNull(value, "Must provide a refresh token value");
        this.value = value;
    }

}
