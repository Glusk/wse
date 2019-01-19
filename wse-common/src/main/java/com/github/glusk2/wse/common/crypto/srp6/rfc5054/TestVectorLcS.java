package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class TestVectorLcS implements SRP6Integer {

    private static final SRP6Integer VALUE =
        new SRP6PrecomputedValue(
            new BigInteger(
                "BEB25379 D1A8581E B5A72767 3A2441EE"
                .replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return VALUE.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return VALUE.bigInteger();
    }
}
