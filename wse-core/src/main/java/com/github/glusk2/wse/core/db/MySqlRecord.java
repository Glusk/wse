package com.github.glusk2.wse.core.db;

import java.math.BigInteger;
import java.security.SecureRandom;
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
    private static final int INTEGER_PAD_SIZE = 32;

    private final DataSource db;
    private final String user;

    public MySqlRecord(DataSource ds, String username) {
        db = ds;
        user = username;
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
                    return
                        new SRP6PrecomputedValue(
                            new BigInteger(
                                1,
                                new SecureRandom()
                                    .generateSeed(INTEGER_PAD_SIZE)
                            )
                        );
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
                    return
                        new SRP6PrecomputedValue(
                            new BigInteger(
                                1,
                                new SecureRandom()
                                    .generateSeed(INTEGER_PAD_SIZE)
                            )
                        );
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
                    return
                        new SRP6PrecomputedValue(
                            new BigInteger(
                                ("894B645E 89E1535B BDAD5B8B 29065053" +
                                 "0801B18E BFBF5E8F AB3C8287 2A3E9BB7"
                                ).replaceAll(" ", ""),
                                HEX_RADIX
                            )
                        );
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
                    return new SRP6PrecomputedValue(new BigInteger("7"));
                }
            });
    }

}
