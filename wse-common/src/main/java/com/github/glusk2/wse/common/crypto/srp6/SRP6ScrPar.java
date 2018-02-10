package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;
import com.github.glusk2.wse.common.util.Mapping;

/** SRP-6 Scrambling Parameter - u. */
public final class SRP6ScrPar implements SRP6Integer {

    private IntermediateDigest u;
    private final Mapping<byte[], SRP6Integer> rule;

    private SRP6Integer cachedValue;

    @SuppressWarnings("checkstyle:parametername")
    public SRP6ScrPar(
        ImmutableMessageDigest imd,
        SRP6Integer A,
        SRP6Integer B,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this(new IntermediateDigest(imd, A, B), rule);
    }

    public SRP6ScrPar(
        IntermediateDigest u,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this.u = u;
        this.rule = rule;
    }

    private SRP6Integer computeInteger() {
        // u = H(A, B)
        return rule.map(u.bytes());
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
