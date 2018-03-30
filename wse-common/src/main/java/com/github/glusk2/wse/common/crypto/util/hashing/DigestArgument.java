package com.github.glusk2.wse.common.crypto.util.hashing;

import javax.xml.bind.DatatypeConverter;

public interface DigestArgument {

    byte[] bytes();

    final class BYTES implements DigestArgument {

        private final byte[] bytes;

        public BYTES(String hex) {
            this(DatatypeConverter.parseHexBinary(hex));
        }

        public BYTES(byte... bytes) {
            this.bytes = bytes;
        }

        @Override
        public byte[] bytes() {
            return bytes;
        }
    }
}
