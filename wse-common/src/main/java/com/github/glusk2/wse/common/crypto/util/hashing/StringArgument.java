package com.github.glusk2.wse.common.crypto.util.hashing;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public final class StringArgument implements DigestArgument {

    private final String string;
    private final Charset charset;

    public StringArgument(String string) {
        this(string, StandardCharsets.UTF_8);
    }

    public StringArgument(String string, Charset charset) {
        this.string = string;
        this.charset = charset;
    }

    @Override
    public byte[] bytes() {
        return string.getBytes(charset);
    }
}
