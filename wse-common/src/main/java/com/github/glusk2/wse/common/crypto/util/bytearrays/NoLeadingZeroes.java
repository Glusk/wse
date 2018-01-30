package com.github.glusk2.wse.common.crypto.util.bytearrays;

import java.util.Arrays;

public final class NoLeadingZeroes implements ByteArray {
    private final ByteArray ba;

    public NoLeadingZeroes(ByteArray ba) {
        this.ba = ba;
    }

    @Override
    public byte[] array() {
        byte[] original = this.ba.array();

        int i = 0;
        while (i < original.length && original[i] == 0) {
            i++;
        }

        if (i == 0) {
            return original;
        }
        return Arrays.copyOfRange(original, i, original.length);
    }
}
