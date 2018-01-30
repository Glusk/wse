package com.github.glusk2.wse.common.crypto.srp6;

import java.sql.SQLException;

public interface SRP6Record {
    SRP6Integer verifier() throws SQLException;
    SRP6Integer salt() throws SQLException;
    SRP6Integer modulus() throws SQLException;
    SRP6Integer generator() throws SQLException;
}
