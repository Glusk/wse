package com.github.glusk2.wse.common.crypto.util.hashing;

public interface DigestArgument {

    byte[] bytes();

    final class RAW_BYTES implements DigestArgument {

        private final byte[] bArr;

        public RAW_BYTES(byte[] bArr) {
            this.bArr = bArr;
        }

        @Override
        public byte[] bytes() {
            return bArr;
        }
    }
}
