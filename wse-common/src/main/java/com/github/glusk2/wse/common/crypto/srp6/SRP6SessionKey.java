package com.github.glusk2.wse.common.crypto.srp6;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;

/** SRP-6 Session Key - K. */
public final class SRP6SessionKey implements DigestArgument {

    private final ImmutableMessageDigest imd;
    @SuppressWarnings("checkstyle:membername")
    private final SRP6Integer S;

    private byte[] cachedKey;

    @SuppressWarnings("checkstyle:parametername")
    public SRP6SessionKey(
        ImmutableMessageDigest imd,
        SRP6Integer S
    ) {
        this.imd = imd;
        this.S = S;
    }

    /**
     * This method implements the SHA_Interleave hash function as described in
     * <a href="http://tools.ietf.org/rfc/rfc2945.txt">RFC2945</a>
     * (section 3.1. Interleaved SHA).
     */
    private byte[] computeKey() {
        byte[] t = S.bytes();
        int off = t.length % 2;
        int halfSize = (t.length - off) / 2;

        byte[] e = new byte[halfSize];
        byte[] o = new byte[halfSize];
        for (int i = off; i < halfSize; i++) {
            e[i - off] = t[2 * i     - off];
            o[i - off] = t[2 * i + 1 - off];
        }
        e = imd.update(e).digest();
        o = imd.update(o).digest();

        byte[] res = new byte[e.length + o.length];
        for (int i = 0; i < res.length / 2; i++) {
            res[2 * i    ] = e[i];
            res[2 * i + 1] = o[i];
        }
        return res;
    }

    @Override
    public byte[] bytes() {
        if (cachedKey == null) {
            cachedKey = computeKey();
        }
        return cachedKey;
    }
}
