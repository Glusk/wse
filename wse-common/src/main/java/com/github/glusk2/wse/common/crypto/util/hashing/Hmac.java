package com.github.glusk2.wse.common.crypto.util.hashing;

public final class Hmac implements DigestArgument {
    private static final byte OPAD_BYTE = 0x5c;
    private static final byte IPAD_BYTE = 0x36;
    public static final int DEFAULT_BLOCK_SIZE = 64;

    private final IntermediateDigest hmac;

    public Hmac(
        ImmutableMessageDigest imd,
        DigestArgument key,
        DigestArgument message
    ) {
        this(imd, key, DEFAULT_BLOCK_SIZE, message);
    }

    public Hmac(
        ImmutableMessageDigest imd,
        DigestArgument key,
        int blockSize,
        DigestArgument message
    ) {
        this(
            imd,
            new XoredArguments(
                new HmacKey(imd, key, blockSize),
                new ValueExpansion(OPAD_BYTE, blockSize)
            ),
            new XoredArguments(
                new HmacKey(imd, key, blockSize),
                new ValueExpansion(IPAD_BYTE, blockSize)
            ),
            message
        );
    }

    public Hmac(
        ImmutableMessageDigest imd,
        DigestArgument opad,
        DigestArgument ipad,
        DigestArgument message
    ) {
        this(
            new IntermediateDigest(
                imd,
                opad,
                new IntermediateDigest(
                    imd,
                    ipad,
                    message
                )
            )
        );
    }

    public Hmac(IntermediateDigest hmac) {
        this.hmac = hmac;
    }

    @Override
    public byte[] bytes() {
        return hmac.bytes();
    }
}
