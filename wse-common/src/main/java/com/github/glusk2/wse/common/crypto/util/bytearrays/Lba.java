package com.github.glusk2.wse.common.crypto.util.bytearrays;

import java.math.BigInteger;

/**
 * Little-Endian {@link ByteArray} representation of a {@link BigInteger}
 * object.
 */
public final class Lba implements ByteArray {

    private final ByteArray ba;

    /**
     * @param  bi
     *         {@link BigInteger} object from which {@code this} little-endian
     *         byte array is to be constructed.
     * @param  size
     *         Required {@link #array()} length. {@link #array()} is padded
     *         with {@code size - (bi.toByteArray().length - #leading_zeroes)}
     *         0 bytes. {@code #leading_zeroes} is the number of leading zeroes
     *         in {@code bi.toByteArray()}.
     */
    public Lba(BigInteger bi, int size) {
        this(
            new ZeroPadded(
                new Reversed(
                    new NoLeadingZeroes(
                        new ByteArray.WRAPPER(bi.toByteArray())
                    )
                ),
                size
            )
        );
    }

    /**
     * @param  bi
     *         {@link BigInteger} object from which {@code this} little-endian
     *         byte array is to be constructed.
     */
    public Lba(BigInteger bi) {
        this(
            new Reversed(
                new NoLeadingZeroes(
                    new ByteArray.WRAPPER(bi.toByteArray())
                )
            )
        );
    }

    private Lba(ByteArray ba) {
        this.ba = ba;
    }

    /**
     * Little-endian byte array representation of the {@link BigInteger} object
     * passed through the constructor.
     */
    @Override
    public byte[] array() {
        return ba.array();
    }
}
