package com.github.glusk2.wse.common.util.string;

import java.nio.charset.Charset;
import java.util.Arrays;

public final class FromString implements CString {

    private final String string;
    private final Charset charset;

    public FromString(String string, Charset charset) {
        this.string = string;
        this.charset = charset;
    }

    @Override
    public String string() {
        return string;
    }

    @Override
    public byte[] bytes() {
        byte[] bytes = string.getBytes(charset);
        return Arrays.copyOfRange(bytes, 0, bytes.length + 1);
    }
}
