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

    private final BigInteger bigIntegerValue;
    private final ByteArray byteArrayValue;

    /**
     * A BigInteger extension that allows specific instantiation options.
     * For example, using this class u can instantiate a BigInteger object,
     * by providing little endian byte array representation.
     */
    private static final class BigIntExt extends BigInteger {
        private static final long serialVersionUID = 1L;

        BigIntExt(ByteArray value, ByteOrder order) {
            this(
                new ByteArray.BRANCH(
                    ByteOrder.BIG_ENDIAN,
                    order,
                    value,
                    new Reversed(value)
                )
            );
        }

        BigIntExt(ByteArray value) {
            super(1, value.array());
        }
    }

    public SRP6PrecomputedValue(BigInteger value) {
        this(value, ByteOrder.LITTLE_ENDIAN);
    }

    public SRP6PrecomputedValue(BigInteger value, ByteOrder order) {
        this(
            value,
            new ByteArray.BRANCH(
                order,
                new Lba(value),
                new Bba(value)
            )
        );
    }

    public SRP6PrecomputedValue(BigInteger value, int byteArrayLength) {
        this(value, byteArrayLength, ByteOrder.LITTLE_ENDIAN);
    }

    public SRP6PrecomputedValue(
        BigInteger value,
        int byteArrayLength,
        ByteOrder order
    ) {
        this(
            value,
            new ByteArray.BRANCH(
                order,
                new Lba(value, byteArrayLength),
                new Bba(value, byteArrayLength)
            )
        );
    }


    public SRP6PrecomputedValue(String hexValue, ByteOrder order) {
        this(DatatypeConverter.parseHexBinary(hexValue), order);
    }

    public SRP6PrecomputedValue(byte[] value, ByteOrder order) {
        this(value, value.length, order);
    }

    public SRP6PrecomputedValue(
        byte[] value,
        int byteArrayLength,
        ByteOrder order
    ) {
        this(new ByteArray.WRAPPER(value), byteArrayLength, order);
    }

    public SRP6PrecomputedValue(
        ByteArray value,
        int byteArrayLength,
        ByteOrder order
    ) {
        this(
            new BigIntExt(value, order),
            new ByteArray.BRANCH(
                order,
                new ZeroPadded(
                    value,
                    byteArrayLength
                ),
                new Reversed(
                    new ZeroPadded(
                        new Reversed(value),
                        byteArrayLength
                    )
                )
            )
        );
    }


    public SRP6PrecomputedValue(
        BigInteger bigIntegerValue,
        ByteArray byteArrayValue
    ) {
        this.bigIntegerValue = bigIntegerValue;
        this.byteArrayValue = byteArrayValue;
    }

    @Override
    public byte[] bytes() {
        return byteArrayValue.array();
    }

    @Override
    public BigInteger bigInteger() {
       return bigIntegerValue;
    }
}
