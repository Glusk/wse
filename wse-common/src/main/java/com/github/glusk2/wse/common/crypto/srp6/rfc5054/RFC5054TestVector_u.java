package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_u implements SRP6Integer {

    private static final SRP6Integer u = 
        new SRP6PrecomputedValue(
            new BigInteger(
                "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019"
                .replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return u.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return u.bigInteger();
    }
}
