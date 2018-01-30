package com.github.glusk2.wse.common.crypto.util.bytearrays;

public final class Reversed implements ByteArray {
    private final ByteArray ba;

    public Reversed(ByteArray ba) {
        this.ba = ba;
    }

    @Override
    public byte[] array() {
        byte[] reversed = this.ba.array().clone();

        for (int i = 0; i < reversed.length / 2; i++) {
            byte tmp = reversed[i];
            reversed[i] = reversed[reversed.length - 1 - i];
            reversed[reversed.length - 1 - i] = tmp;
        }

        return reversed;
    }
}
