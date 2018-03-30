package com.github.glusk2.wse.common.crypto.util.hashing;

import java.util.Arrays;

public final class ValueExpansion implements DigestArgument {

    private final byte value;
    private final int length;

    public ValueExpansion(byte value, int length) {
        this.value = value;
        this.length = length;
    }

    @Override
    public byte[] bytes() {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
