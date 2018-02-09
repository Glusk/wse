package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;
import java.nio.ByteOrder;

import javax.xml.bind.DatatypeConverter;

import com.github.glusk2.wse.common.crypto.util.bytearrays.Bba;
import com.github.glusk2.wse.common.crypto.util.bytearrays.ByteArray;
import com.github.glusk2.wse.common.crypto.util.bytearrays.Lba;
import com.github.glusk2.wse.common.crypto.util.bytearrays.Reversed;
import com.github.glusk2.wse.common.crypto.util.bytearrays.ZeroPadded;

/**
 * An SRP6 precomputed integer value.
 * <p>
 * This class accepts either a byte array or a {@link BigInteger}
 * representation of a SRP6 variable. It configures the representation
 * via the constructors.
 */
public final class SRP6PrecomputedValue implements SRP6Integer {

    private final BigInteger bi;
    private final ByteArray ba;

    /**
     * A BigInteger extension that allows specific instantiation options.
     * For example, using this class u can instantiate a BigInteger object,
     * by providing little endian byte array representation.
     */
    private static final class BigIntExt extends BigInteger {
        private static final long serialVersionUID = 1L;

        BigIntExt(ByteArray ba, ByteOrder bo) {
            this(
                new ByteArray.BRANCH(
                    ByteOrder.BIG_ENDIAN,
                    bo,
                    ba,
                    new Reversed(ba)
                )
            );
        }

        BigIntExt(ByteArray ba) {
            super(1, ba.array());
        }
    }

    public SRP6PrecomputedValue(BigInteger bi) {
        this(bi, ByteOrder.LITTLE_ENDIAN);
    }

    public SRP6PrecomputedValue(BigInteger bi, ByteOrder bo) {
        this(
            bi,
            new ByteArray.BRANCH(
                bo,
                new Lba(bi),
                new Bba(bi)
            )
        );
    }

    public SRP6PrecomputedValue(BigInteger bi, int size) {
        this(bi, size, ByteOrder.LITTLE_ENDIAN);
    }

    public SRP6PrecomputedValue(BigInteger bi, int size, ByteOrder bo) {
        this(
            bi,
            new ByteArray.BRANCH(
                bo,
                new Lba(bi, size),
                new Bba(bi, size)
            )
        );
    }


    public SRP6PrecomputedValue(String hex, ByteOrder order) {
        this(DatatypeConverter.parseHexBinary(hex), order);
    }

    public SRP6PrecomputedValue(byte[] arr, ByteOrder order) {
        this(arr, arr.length, order);
    }

    public SRP6PrecomputedValue(byte[] arr, int size, ByteOrder bo) {
        this(new ByteArray.WRAPPER(arr), size, bo);
    }

    public SRP6PrecomputedValue(ByteArray arr, int size, ByteOrder bo) {
        this(
            new BigIntExt(arr, bo),
            new ByteArray.BRANCH(
                bo,
                new ZeroPadded(
                    arr,
                    size
                ),
                new Reversed(
                    new ZeroPadded(
                        new Reversed(arr),
                        size
                    )
                )
            )
        );
    }


    private SRP6PrecomputedValue(BigInteger bi, ByteArray ba) {
        this.bi = bi;
        this.ba = ba;
    }

    @Override
    public byte[] bytes() {
        return ba.array();
    }

    @Override
    public BigInteger bigInteger() {
       return bi;
    }
}
