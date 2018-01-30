package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.util.Mapping;

public final class SRP6Verifier implements SRP6Integer {

    private final SRP6Integer srp6_N;
    private final SRP6Integer srp6_g;
    private final SRP6Integer srp6_x;
    private final Mapping<BigInteger, SRP6Integer> rule;

    private SRP6Integer v;

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

    private SRP6Integer compute_v() {
        BigInteger N = srp6_N.bigInteger();
        BigInteger g = srp6_g.bigInteger();
        BigInteger x = srp6_x.bigInteger();

        // v = g^x
        return rule.map(g.modPow(x, N));
    }

    @Override
    public byte[] bytes() {
        if (v == null) {
            v = compute_v();
        }
        return v.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (v == null) {
            v = compute_v();
        }
        return v.bigInteger();
    }
}
