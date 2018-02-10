package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.util.Mapping;

/** SRP-6 Verifier - v. */
@SuppressWarnings("checkstyle:membername")
public final class SRP6Verifier implements SRP6Integer {

    private final SRP6Integer srp6_N;
    private final SRP6Integer srp6_g;
    private final SRP6Integer srp6_x;
    private final Mapping<BigInteger, SRP6Integer> rule;

    private SRP6Integer cachedValue;

    @SuppressWarnings("checkstyle:parametername")
    public SRP6Verifier(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer x,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this.srp6_N = N;
        this.srp6_g = g;
        this.srp6_x = x;
        this.rule = rule;
    }

    @SuppressWarnings("checkstyle:localvariablename")
    private SRP6Integer computeInteger() {
        BigInteger N = srp6_N.bigInteger();
        BigInteger g = srp6_g.bigInteger();
        BigInteger x = srp6_x.bigInteger();

        // v = g^x
        return rule.map(g.modPow(x, N));
    }

    @Override
    public byte[] bytes() {
        if (cachedValue == null) {
            cachedValue = computeInteger();
        }
        return cachedValue.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (cachedValue == null) {
            cachedValue = computeInteger();
        }
        return cachedValue.bigInteger();
    }
}
