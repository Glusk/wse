package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.util.Mapping;

/**
 * An SRP6 Server Public Ephemeral value - B.
 */
public final class SRP6SrvPubEphVal implements SRP6Integer {
    private final SRP6Integer srp6_k;
    private final SRP6Integer srp6_b;
    private final SRP6Integer srp6_v;
    private final SRP6Integer srp6_g;
    private final SRP6Integer srp6_N;
    private final Mapping<BigInteger, SRP6Integer> rule;

    private SRP6Integer B;

    public SRP6SrvPubEphVal(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer v,
        SRP6Integer b,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this(
            N,
            g,
            new SRP6PrecomputedValue(
                new BigInteger("3")
            ),
            v,
            b,
            rule
        );
    }

    public SRP6SrvPubEphVal(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer k,
        SRP6Integer v,
        SRP6Integer b,
        Mapping<BigInteger, SRP6Integer> rule
    ) {
        this.srp6_N = N;
        this.srp6_g = g;
        this.srp6_k = k;
        this.srp6_v = v;
        this.srp6_b = b;
        this.rule = rule;
    }

    @SuppressWarnings("checkstyle:localvariablename")
    private SRP6Integer computeB() {
        BigInteger k = srp6_k.bigInteger();
        BigInteger b = srp6_b.bigInteger();
        BigInteger v = srp6_v.bigInteger();
        BigInteger g = srp6_g.bigInteger();
        BigInteger N = srp6_N.bigInteger();

        // B = kv + g^b
        return rule.map(k.multiply(v).add(g.modPow(b, N)).mod(N));
    }

    @Override
    public byte[] bytes() {
        if (B == null) {
            B = computeB();
        }
        return B.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (B == null) {
            B = computeB();
        }
        return B.bigInteger();
    }
}
