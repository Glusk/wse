package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.util.Mapping;

public final class SRP6ScrPar implements SRP6Integer {

    private final ImmutableMessageDigest imd;
    private final Mapping<byte[], SRP6Integer> rule;
    private final SRP6Integer A;
    private final SRP6Integer B;

    private SRP6Integer u;

    public SRP6ScrPar(
        ImmutableMessageDigest imd,
        SRP6Integer A,
        SRP6Integer B,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this.imd = imd;
        this.A = A;
        this.B = B;
        this.rule = rule;
    }

    private SRP6Integer compute_u() {
        // u = H(A, B)
        return rule.map(imd.update(A, B).digest());
    }

    @Override
    public byte[] bytes() {
        if (u == null) {
            u = compute_u();
        }
        return u.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (u == null) {
            u = compute_u();
        }
        return u.bigInteger();
    }
}
