package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;
import com.github.glusk2.wse.common.util.Mapping;

public final class SRP6PrivateKey implements SRP6Integer {

    private final ImmutableMessageDigest imd;
    private final SRP6Integer s;
    private final DigestArgument p;
    private final Mapping<byte[], SRP6Integer> rule;

    private SRP6Integer x;

    public SRP6PrivateKey(
        ImmutableMessageDigest imd,
        SRP6Integer s,
        String I,
        String P,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this(imd, s, I, P, StandardCharsets.UTF_8, rule);
    }

    public SRP6PrivateKey(
        ImmutableMessageDigest imd,
        SRP6Integer s,
        String I,
        String P,
        Charset charset,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this(
            imd,
            s,
            new IntermediateDigest(
                imd,
                new StringArgument(I + ":" + P, charset)
            ),
            rule
        );
    }

    public SRP6PrivateKey(
        ImmutableMessageDigest imd,
        SRP6Integer s,
        DigestArgument p,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this.imd = imd;
        this.rule = rule;
        this.p = p;
        this.s = s;
    }

    private SRP6Integer compute_x() {
        // H(salt | H(username | ":" | password)) = H(salt | p)
        return rule.map(imd.update(s, p).digest());
    }

    @Override
    public byte[] bytes() {
        if (x == null) {
            x = compute_x();
        }
        return x.bytes();
    }

    @Override
    public BigInteger bigInteger() {
        if (x == null) {
            x = compute_x();
        }
        return x.bigInteger();
    }
}
