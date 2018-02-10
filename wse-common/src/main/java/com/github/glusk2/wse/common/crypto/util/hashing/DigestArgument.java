package com.github.glusk2.wse.common.crypto.util.hashing;

public interface DigestArgument {

    byte[] bytes();

    final class BYTES implements DigestArgument {

        private final byte[] bytes;

        public BYTES(byte... bytes) {
            this.bytes = bytes;
        }

        @Override
        public byte[] bytes() {
            return bytes;
        }
    }
}
