package com.github.glusk2.wse.common.crypto.srp6.rfc5054;

import java.math.BigInteger;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;

@SuppressWarnings("checkstyle:typename")
public final class RFC5054TestVector_B implements SRP6Integer {

    private static final SRP6Integer VALUE =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1" +
                 "05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9" +
                 "B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885" +
                 "D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A" +
                 "00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238" +
                 "A8E3FB00 4B117B58").replace(" ", ""),
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
