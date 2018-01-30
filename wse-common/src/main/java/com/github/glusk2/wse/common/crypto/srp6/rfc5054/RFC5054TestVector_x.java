package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_x implements SRP6Integer {

    private static final SRP6Integer x =
        new SRP6PrecomputedValue(
            new BigInteger(
                "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124"
                .replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return x.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return x.bigInteger();
    }
}
