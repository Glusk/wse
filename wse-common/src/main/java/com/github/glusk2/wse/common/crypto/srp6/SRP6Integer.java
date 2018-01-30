package com.github.glusk2.wse.common.crypto.srp6;

import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;

public interface SRP6Integer extends DigestArgument {
    default String string() {
        return DatatypeConverter.printHexBinary(bytes());
    }
    BigInteger bigInteger();
}
