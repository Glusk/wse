package com.github.glusk2.wse.core.db;

import java.sql.SQLException;

import javax.xml.bind.DatatypeConverter;

public interface Session {
    byte[] key() throws SQLException;
    void update(String key) throws SQLException;
    default void update(byte[] key) throws SQLException {
        update(DatatypeConverter.printHexBinary(key));
    }
}
