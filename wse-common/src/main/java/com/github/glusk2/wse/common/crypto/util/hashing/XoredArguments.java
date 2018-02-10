package com.github.glusk2.wse.common.crypto.util.hashing;

import java.math.BigInteger;
import java.util.Arrays;

public final class XoredArguments implements DigestArgument {

    private final DigestArgument[] args;

    public XoredArguments(DigestArgument... args) {
        this.args = args;
    }

    @Override
    public byte[] bytes() {
        return Arrays.stream(args)
                     .map(arg -> new BigInteger(arg.bytes()))
                     .reduce(BigInteger.ZERO, (i, j) -> i.xor(j))
                     .toByteArray();
    }

}
