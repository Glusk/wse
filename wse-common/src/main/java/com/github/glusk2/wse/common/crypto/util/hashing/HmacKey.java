package com.github.glusk2.wse.common.crypto.util.hashing;

import java.util.Arrays;

public final class HmacKey implements DigestArgument {

    private final ImmutableMessageDigest imd;
    private final DigestArgument key;
    private final int blockSize;

    public HmacKey(
        ImmutableMessageDigest imd,
        DigestArgument key,
        int blockSize
    ) {
        this.imd = imd;
        this.key = key;
        this.blockSize = blockSize;
    }

    @Override
    public byte[] bytes() {
        byte[] keyBytes = key.bytes();
        if (keyBytes.length <= blockSize) {
            return Arrays.copyOf(keyBytes, blockSize);
        }
        return imd.update(key).digest();
    }
}
