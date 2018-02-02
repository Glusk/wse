package com.github.glusk2.wse.core.db;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.github.glusk2.wse.common.util.string.CString;
import com.github.glusk2.wse.common.util.string.FromString;
import com.jcabi.jdbc.JdbcSession;
import com.jcabi.jdbc.Outcome;
import com.jcabi.jdbc.SingleOutcome;

public final class MySqlRealm implements Realm {

    private final DataSource db;
    private final int id;

    public MySqlRealm(DataSource db, int id) {
        this.db = db;
        this.id = id;
    }

    @Override
    public CString address() throws SQLException {
        return
            new FromString(
                new JdbcSession(this.db)
                    .sql(
                        "SELECT CONCAT(INET_NTOA(ip_address), ':', port) " +
                        "FROM realm " +
                        "WHERE id = ?")
                    .set(this.id)
                    .select(new SingleOutcome<String>(String.class)),
                StandardCharsets.UTF_8
            );
    }

    @Override
    public CString name() throws SQLException {
        return
            new FromString(
                new JdbcSession(this.db)
                    .sql("SELECT name FROM realm WHERE id = ?")
                    .set(this.id)
                    .select(new SingleOutcome<String>(String.class)),
                StandardCharsets.UTF_8
            );
    }

    @Override
    public float population() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT population_level FROM realm WHERE id = ?")
            .set(this.id)
            .select(new Outcome<Float>() {
                 @Override
                 public Float handle(
                     final ResultSet rs,
                     final Statement stmt
                 ) throws SQLException {
                     float res = 0;
                     if (rs.next()) {
                         res = rs.getFloat(1);
                     }
                     return res;
                 }
             });
    }

    @Override
    public byte type() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT type FROM realm WHERE id = ?")
            .set(this.id)
            .select(new SingleOutcome<Byte>(Byte.class));
    }

    @Override
    public boolean isLocked() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT is_locked FROM realm WHERE id = ?")
            .set(this.id)
            .select(new SingleOutcome<Boolean>(Boolean.class));
    }

    @Override
    public byte flags() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT flags FROM realm WHERE id = ?")
            .set(this.id)
            .select(new SingleOutcome<Byte>(Byte.class));
    }

    @Override
    public byte location() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT location FROM realm WHERE id = ?")
            .set(this.id)
            .select(new SingleOutcome<Byte>(Byte.class));
    }

    @Override
    public ByteBuffer build() throws SQLException {
        return new JdbcSession(this.db)
            .sql(
                "SELECT version1, version2, version3, build " +
                "FROM realm WHERE id = ?")
            .set(this.id)
            .select(new Outcome<ByteBuffer>() {
                @Override
                public ByteBuffer handle(
                    final ResultSet rs,
                    final Statement stmt
                ) throws SQLException {
                    if (rs.next()) {
                        return
                            (ByteBuffer) ByteBuffer
                            .allocate(1 + 1 + 1 + 2)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .put(rs.getByte("version1"))
                            .put(rs.getByte("version2"))
                            .put(rs.getByte("version3"))
                            .putShort(rs.getShort("build"))
                            .flip();
                    }
                    throw new SQLException(
                        String.format(
                            "No results for realm(id=%d) build.",
                            id
                        )
                    );
                }
            });
    }

    @Override
    public byte characterCount(final String username) throws SQLException {
        return new JdbcSession(this.db)
                .sql(
                    "SELECT IFNULL ( " +
                        "(SELECT count FROM characters_per_realm " +
                        "WHERE realm_id = ? AND record_username = ?), " +
                    "0)"
                )
                .set(this.id)
                .set(username)
                .select(new SingleOutcome<Byte>(Byte.class));
    }

    @Override
    public int id() {
        return this.id;
    }
}
