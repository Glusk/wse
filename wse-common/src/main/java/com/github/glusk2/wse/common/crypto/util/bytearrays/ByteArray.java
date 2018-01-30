package com.github.glusk2.wse.common.crypto.util.bytearrays;

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
}
