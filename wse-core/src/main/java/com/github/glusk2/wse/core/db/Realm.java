package com.github.glusk2.wse.core.db;

import java.nio.ByteBuffer;
import java.sql.SQLException;

import com.github.glusk2.wse.common.util.string.CString;

public interface Realm {
    int id();
    byte type() throws SQLException;
    boolean isLocked() throws SQLException;
    byte flags() throws SQLException;
    CString address() throws SQLException;
    CString name() throws SQLException;
    float population() throws SQLException;
    byte location() throws SQLException;
    ByteBuffer build() throws SQLException;
    byte characterCount(String user) throws SQLException;
}
