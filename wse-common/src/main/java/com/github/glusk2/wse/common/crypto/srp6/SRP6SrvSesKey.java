package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.util.Mapping;

public final class SRP6SrvSesKey implements SRP6Integer {
    private final SRP6Integer srp6_N;
    private final SRP6Integer srp6_A;
    private final SRP6Integer srp6_v;
    private final SRP6Integer srp6_b;
    private final SRP6Integer srp6_u;
    private final Mapping<BigInteger, SRP6Integer> rule;

    private SRP6Integer S;

    public SRP6SrvSesKey(
        SRP6Integer N,
        SRP6Integer A,
        SRP6Integer v,
        SRP6Integer u,
        SRP6Integer b,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this.srp6_N = N;
        this.srp6_A = A;
        this.srp6_v = v;
        this.srp6_u = u;
        this.srp6_b = b;
        this.rule = rule;
    }

    @SuppressWarnings("checkstyle:localvariablename")
    private SRP6Integer compute_S() {
        BigInteger N = srp6_N.bigInteger();
        BigInteger A = srp6_A.bigInteger();
        BigInteger v = srp6_v.bigInteger();
        BigInteger b = srp6_b.bigInteger();
        BigInteger u = srp6_u.bigInteger();

        // S = (A*v^u)^b
        return rule.map(A.multiply(v.modPow(u, N)).modPow(b, N));
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
