package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

@SuppressWarnings("checkstyle:typename")
public final class RFC5054TestVector_A implements SRP6Integer {

    private static final SRP6Integer VALUE =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB" +
                 "72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E" +
                 "0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251" +
                 "71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261" +
                 "EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36" +
                 "72FAC47B 0769447B").replace(" ", ""),
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
