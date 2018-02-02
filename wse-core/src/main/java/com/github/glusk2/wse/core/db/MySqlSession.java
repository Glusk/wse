package com.github.glusk2.wse.core.db;
import java.sql.SQLException;

import javax.sql.DataSource;
import javax.xml.bind.DatatypeConverter;

import com.jcabi.jdbc.JdbcSession;
import com.jcabi.jdbc.Outcome;
import com.jcabi.jdbc.SingleOutcome;

public final class MySqlSession implements Session {

    private final DataSource db;
    private final String username;

    public MySqlSession(DataSource db, String username) {
        this.db = db;
        this.username = username;
    }

    @Override
    public byte[] key() throws SQLException {
        return DatatypeConverter.parseHexBinary(
            new JdbcSession(this.db)
                .sql(
                    "SELECT session_key " +
                    "FROM session " +
                    "WHERE record_username = ?")
                .set(this.username)
                .select(new SingleOutcome<String>(String.class))
            );
    }

    @Override
    public void update(final String key) throws SQLException {
        new JdbcSession(this.db)
            .sql(
                "INSERT INTO session (record_username, session_key) " +
                "VALUES (?, ?) " +
                "ON DUPLICATE KEY UPDATE session_key = ?")
            .set(username)
            .set(key)
            .set(key)
            .update(Outcome.VOID);
    }
}
