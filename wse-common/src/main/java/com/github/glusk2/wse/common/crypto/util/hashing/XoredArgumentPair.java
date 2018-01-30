package com.github.glusk2.wse.common.crypto.util.hashing;

import java.math.BigInteger;

public final class XoredArgumentPair implements DigestArgument {

    private final DigestArgument arg1;
    private final DigestArgument arg2;

    public XoredArgumentPair(DigestArgument arg1, DigestArgument arg2) {
        this.arg1 = arg1;
        this.arg2 = arg2;
    }

    @Override
    public byte[] bytes() {
        return
            new BigInteger(
                arg1.bytes()
            ).xor(
                new BigInteger(
                    arg2.bytes()
                )
            ).toByteArray();
    }

}
