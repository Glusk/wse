package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

@SuppressWarnings("checkstyle:typename")
public final class RFC5054TestVector_a implements SRP6Integer {

    private static final SRP6Integer VALUE =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56" +
                 "AFD529DD DA2D4393").replace(" ", ""),
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
