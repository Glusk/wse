package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_N implements SRP6Integer {

    private static final SRP6Integer N =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B" +
                 "9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0" +
                 "E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6" +
                 "CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC" +
                 "68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B" +
                 "9FC61D2F C0EB06E3").replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return N.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return N.bigInteger();
    }
}
