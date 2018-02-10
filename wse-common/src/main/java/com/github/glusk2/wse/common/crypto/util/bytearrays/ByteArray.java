package com.github.glusk2.wse.common.crypto.util.bytearrays;

import java.nio.ByteOrder;

public interface ByteArray {

    byte[] array();

    final class WRAPPER implements ByteArray {

        private final byte[] arr;

        public WRAPPER(byte[] arr) {
            this.arr = arr;
        }

        @Override
        public byte[] array() {
            return arr;
        }
    }

    final class BRANCH implements ByteArray {

        private final ByteOrder refOrder;
        private final ByteOrder order;
        private final ByteArray reference;
        private final ByteArray alternative;

        public BRANCH(
            ByteOrder order,
            ByteArray reference,
            ByteArray alternative
        ) {
            this(ByteOrder.LITTLE_ENDIAN, order, reference, alternative);
        }

        public BRANCH(
            ByteOrder refOrder,
            ByteOrder order,
            ByteArray reference,
            ByteArray alternative
        ) {
            this.refOrder = refOrder;
            this.order = order;
            this.reference = reference;
            this.alternative = alternative;
        }

        @Override
        public byte[] array() {
            if (order == refOrder) {
                return reference.array();
            }
            return alternative.array();
        }
    }
}
