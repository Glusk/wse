package com.github.glusk2.wse.common.crypto.srp6;

import java.nio.ByteBuffer;
import java.sql.SQLException;

import com.github.glusk2.wse.common.util.Digitizable;

public interface SRP6Record extends Digitizable {
    SRP6Integer verifier() throws SQLException;
    SRP6Integer salt() throws SQLException;
    SRP6Integer modulus() throws SQLException;
    SRP6Integer generator() throws SQLException;
    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    default byte[] digits() throws Exception {
        byte[] v = verifier().bytes();
        byte[] s = salt().bytes();
        byte[] N = modulus().bytes();
        byte[] g = generator().bytes();
        return ByteBuffer.allocate(v.length + s.length + N.length + g.length)
              .put(v)
              .put(s)
              .put(N)
              .put(g)
              .array();
    }
}
