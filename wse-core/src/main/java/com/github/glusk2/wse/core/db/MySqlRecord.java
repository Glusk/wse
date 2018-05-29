package com.github.glusk2.wse.core.db;

import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.jcabi.jdbc.JdbcSession;
import com.jcabi.jdbc.Outcome;

public final class MySqlRecord implements SRP6Record {

    private static final int HEX_RADIX = 16;

    private final DataSource db;
    private final String user;
    private final SRP6Record fakeRecord;

    public MySqlRecord(DataSource ds, String username, SRP6Record fake) {
        db = ds;
        user = username;
        fakeRecord = fake;
    }

    @Override
    public SRP6Integer verifier() throws SQLException {
        return new JdbcSession(db)
            .sql("SELECT verifier FROM srp6_record WHERE username = ?")
            .set(user)
            .select(new Outcome<SRP6Integer>() {
                @Override
                public SRP6Integer handle(
                    final ResultSet rs,
                    final Statement st
                ) throws SQLException {
                    if (rs.next()) {
                        return
                            new SRP6PrecomputedValue(
                                new BigInteger(rs.getString(1), HEX_RADIX)
                            );
                    }
                    return fakeRecord.verifier();
                }
            });
    }

    @Override
    public SRP6Integer salt() throws SQLException {
        return new JdbcSession(db)
            .sql("SELECT salt FROM srp6_record WHERE username = ?")
            .set(user)
            .select(new Outcome<SRP6Integer>() {
                @Override
                public SRP6Integer handle(
                    final ResultSet rs,
                    final Statement st
                ) throws SQLException {
                    if (rs.next()) {
                        return
                            new SRP6PrecomputedValue(
                                new BigInteger(rs.getString(1), HEX_RADIX)
                            );
                    }
                    return fakeRecord.salt();
                }
            });
    }

    @Override
    public SRP6Integer modulus() throws SQLException {
        return new JdbcSession(db)
            .sql("SELECT prime FROM srp6_record WHERE username = ?")
            .set(user)
            .select(new Outcome<SRP6Integer>() {
                @Override
                public SRP6Integer handle(
                    final ResultSet rs,
                    final Statement st
                ) throws SQLException {
                    if (rs.next()) {
                        return
                            new SRP6PrecomputedValue(
                                new BigInteger(rs.getString(1), HEX_RADIX)
                            );
                    }
                    return fakeRecord.modulus();
                }
            });
    }

    @Override
    public SRP6Integer generator() throws SQLException {
        return new JdbcSession(db)
            .sql("SELECT generator FROM srp6_record WHERE username = ?")
            .set(user)
            .select(new Outcome<SRP6Integer>() {
                @Override
                public SRP6Integer handle(
                    final ResultSet rs,
                    final Statement st
                ) throws SQLException {
                    if (rs.next()) {
                        return
                            new SRP6PrecomputedValue(
                                new BigInteger(rs.getString(1), HEX_RADIX)
                            );
                    }
                    return fakeRecord.generator();
                }
            });
    }

}
