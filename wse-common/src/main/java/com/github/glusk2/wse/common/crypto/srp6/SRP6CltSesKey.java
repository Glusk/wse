package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.util.Mapping;

public final class SRP6CltSesKey implements SRP6Integer {

    private final SRP6Integer srp6_N;
    private final SRP6Integer srp6_g;
    private final SRP6Integer srp6_k;
    private final SRP6Integer srp6_x;
    private final SRP6Integer srp6_u;
    private final SRP6Integer srp6_a;
    private final SRP6Integer srp6_B;
    private final Mapping<BigInteger, SRP6Integer> rule;

    private SRP6Integer S;

    public SRP6CltSesKey(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer x,
        SRP6Integer u,
        SRP6Integer a,
        SRP6Integer B,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this(
            N,
            g,
            new SRP6PrecomputedValue(new BigInteger("3")),
            x,
            u,
            a,
            B,
            rule
        );
    }

    @SuppressWarnings("checkstyle:parameternumber")
    public SRP6CltSesKey(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer k,
        SRP6Integer x,
        SRP6Integer u,
        SRP6Integer a,
        SRP6Integer B,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this.srp6_N = N;
        this.srp6_g = g;
        this.srp6_k = k;
        this.srp6_x = x;
        this.srp6_u = u;
        this.srp6_a = a;
        this.srp6_B = B;
        this.rule = rule;
    }

    @SuppressWarnings("checkstyle:localvariablename")
    private SRP6Integer compute_S() {
        BigInteger N = srp6_N.bigInteger();
        BigInteger g = srp6_g.bigInteger();
        BigInteger k = srp6_k.bigInteger();
        BigInteger x = srp6_x.bigInteger();
        BigInteger u = srp6_u.bigInteger();
        BigInteger a = srp6_a.bigInteger();
        BigInteger B = srp6_B.bigInteger();

        //S = (B - kg^x) ^ (a + ux)
        return rule.map(
            B.subtract(k.multiply(g.modPow(x, N)))
            .modPow(a.add(u.multiply(x)), N));
    }

    @Override
    public byte[] bytes() {
        if (S == null) {
            S = compute_S();
        }
        return S.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (S == null) {
            S = compute_S();
        }
        return S.bigInteger();
    }
}
