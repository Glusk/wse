package com.github.glusk2.wse.common.crypto.util.bytearrays;

import java.util.Arrays;

public final class ZeroPadded implements ByteArray {
    private final ByteArray bat;
    private final int newSize;

    public ZeroPadded(ByteArray bat, int newSize) {
        this.bat = bat;
        this.newSize = newSize;
    }

    @Override
    public byte[] array() {
        byte[] original = this.bat.array();
        if (this.newSize < original.length) {
            throw new RuntimeException(
                String.format(
                    "New size is smaller than original array length. " +
                    "Original size: %d, new size: %d. Possible loss of data!",
                    original.length, this.newSize)
            );
        }

        if (this.newSize == original.length) {
            return original;
        }
        return Arrays.copyOfRange(original, 0, this.newSize);
    }
}
