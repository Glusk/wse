package com.github.glusk2.wse.common.crypto.util.bytearrays;

import java.math.BigInteger;

public final class Bba implements ByteArray {
    private final ByteArray ba;

    public Bba(BigInteger bi, int size) {
        this(
            new Reversed(
                new ZeroPadded(
                    new Reversed(
                        new NoLeadingZeroes(
                            new ByteArray.WRAPPER(bi.toByteArray())
                        )
                    ),
                    size
                )
            )
        );
    }

    public Bba(BigInteger bi) {
        this(
            new NoLeadingZeroes(
                new ByteArray.WRAPPER(bi.toByteArray())
            )
        );
    }

    private Bba(ByteArray ba) {
        this.ba = ba;
    }

    @Override
    public byte[] array() {
        return ba.array();
    }
}
