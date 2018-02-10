package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;
import com.github.glusk2.wse.common.util.Mapping;

/** SRP-6 Private Key - x. */
@SuppressWarnings("checkstyle:parametername")
public final class SRP6PrivateKey implements SRP6Integer {

    private final DigestArgument x;
    private final Mapping<byte[], SRP6Integer> rule;

    private SRP6Integer cachedValue;

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
        this(new IntermediateDigest(imd, s, p), rule);
    }

    public SRP6PrivateKey(
        DigestArgument x,
        Mapping<byte[], SRP6Integer> rule
    ) {
        this.x = x;
        this.rule = rule;
    }

    private SRP6Integer computeInteger() {
        // H(salt | H(username | ":" | password)) = H(salt | p)
        return rule.map(x.bytes());
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
