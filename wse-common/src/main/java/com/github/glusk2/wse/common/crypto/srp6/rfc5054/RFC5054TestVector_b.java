package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_b implements SRP6Integer {

    private static final SRP6Integer b = 
        new SRP6PrecomputedValue(
            new BigInteger(
                ("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4" +
                 "9E61F5D1 05284D20").replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return b.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return b.bigInteger();
    }
}
