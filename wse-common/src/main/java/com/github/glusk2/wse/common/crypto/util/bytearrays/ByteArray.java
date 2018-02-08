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

    final class FILTERED_BY_ORDER implements ByteArray {

        private final ByteOrder filter;
        private final ByteArray littleEndianArray;
        private final ByteArray bigEndianArray;

        public FILTERED_BY_ORDER(
            ByteOrder filter,
            ByteArray littleEndianArray,
            ByteArray bigEndianArray
        ) {
            this.filter = filter;
            this.littleEndianArray = littleEndianArray;
            this.bigEndianArray = bigEndianArray;
        }

        @Override
        public byte[] array() {
            if (filter == ByteOrder.LITTLE_ENDIAN) {
                return littleEndianArray.array();
            }
            return bigEndianArray.array();
        }
    }
}
