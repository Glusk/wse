package com.github.glusk2.wse.common.crypto.srp6;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;

/** SRP-6 Server Session Proof - M2. */
public final class SRP6SrvSesProof implements DigestArgument {

    private final IntermediateDigest proof;

    private byte[] cachedProofBytes;

    public SRP6SrvSesProof(
        ImmutableMessageDigest imd,
        SRP6Integer A,
        DigestArgument M,
        DigestArgument K
    ) {
        this(new IntermediateDigest(imd, A, M, K));
    }

    public SRP6SrvSesProof(IntermediateDigest proof) {
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
