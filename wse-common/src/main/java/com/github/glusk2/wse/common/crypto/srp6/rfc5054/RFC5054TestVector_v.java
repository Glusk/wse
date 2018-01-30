package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

public final class RFC5054TestVector_v implements SRP6Integer {

    private static final SRP6Integer v =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A" +
                 "9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59" +
                 "F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84" +
                 "00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04" +
                 "E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245" +
                 "DB2BE315 E2099AFB").replace(" ", ""),
                16
            ),
            ByteOrder.BIG_ENDIAN
        );

    @Override
    public byte[] bytes() {
        return v.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        return v.bigInteger();
    }
}
