package com.github.glusk2.wse.common.crypto.srp6;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.XoredArguments;

/** SRP-6 Client Proof Of Session Key - M1. */
@SuppressWarnings("checkstyle:parametername")
public final class SRP6CltSesProof implements DigestArgument {

    private final IntermediateDigest proof;

    private byte[] cachedProofBytes;

    @SuppressWarnings("checkstyle:parameternumber")
    public SRP6CltSesProof(
        ImmutableMessageDigest imd,
        SRP6Integer N,
        SRP6Integer g,
        String I,
        SRP6Integer s,
        SRP6Integer A,
        SRP6Integer B,
        DigestArgument K
    ) {
        this(imd, N, g, I, StandardCharsets.UTF_8, s, A, B, K);
    }

    @SuppressWarnings("checkstyle:parameternumber")
    public SRP6CltSesProof(
        ImmutableMessageDigest imd,
        SRP6Integer N,
        SRP6Integer g,
        String I,
        Charset charset,
        SRP6Integer s,
        SRP6Integer A,
        SRP6Integer B,
        DigestArgument K
    ) {
        this(
            new IntermediateDigest(
                imd,
                new XoredArguments(
                    new IntermediateDigest(imd, N),
                    new IntermediateDigest(imd, g)
                ),
                new IntermediateDigest(
                    imd,
                    new StringArgument(
                        I,
                        charset
                    )
                ),
                s,
                A,
                B,
                K
            )
        );
    }

    public SRP6CltSesProof(IntermediateDigest proof) {
        this.proof = proof;
    }

    @Override
    public byte[] bytes() {
        if (cachedProofBytes == null) {
            cachedProofBytes = proof.bytes();
        }
        return cachedProofBytes;
    }
}
