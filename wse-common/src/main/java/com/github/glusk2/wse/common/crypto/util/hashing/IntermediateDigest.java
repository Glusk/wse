package com.github.glusk2.wse.common.crypto.util.hashing;

public final class IntermediateDigest implements DigestArgument {

    private final ImmutableMessageDigest imd;
    private final DigestArgument[] args;

    public IntermediateDigest(
        ImmutableMessageDigest imd,
        DigestArgument... args
    ) {
        this.imd = imd;
        this.args = args;
    }

    @Override
    public byte[] bytes() {
        return imd.update(args).digest();
    }

}
