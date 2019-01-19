package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class TestVectorUcS implements SRP6Integer {

    private static final SRP6Integer VALUE =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA" +
                 "F271A10D 233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F" +
                 "0876E2D0 13800D6C 41BB59B6 D5979B5C 00A172B4 A2A5903A" +
                 "0BDCAF8A 709585EB 2AFAFA8F 3499B200 210DCC1F 10EB3394" +
                 "3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D C346D7E4 74B29EDE" +
                 "8A469FFE CA686E5A").replace(" ", ""),
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
