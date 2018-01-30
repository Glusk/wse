package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_k implements SRP6Integer {

    private static final SRP6Integer k =
        new SRP6PrecomputedValue(
            new BigInteger(
                "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F"
                .replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return k.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return k.bigInteger();
    }
}
