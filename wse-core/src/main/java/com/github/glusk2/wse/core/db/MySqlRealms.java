package com.github.glusk2.wse.core.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.jcabi.jdbc.JdbcSession;
import com.jcabi.jdbc.ListOutcome;
import com.jcabi.jdbc.Outcome;

public final class MySqlRealms implements Realms {

    private final DataSource db;
    private ListOutcome.Mapping<Realm> realmMapping;

    public MySqlRealms(DataSource db) {
        this(
            db,
            (ResultSet rs ) -> new MySqlRealm(db, rs.getByte(1))
        );
    }
    public MySqlRealms(DataSource db, ListOutcome.Mapping<Realm> realmMapping) {
        this.db = db;
        this.realmMapping = realmMapping;
    }

    @Override
    public Iterable<Realm> iterate() throws SQLException {
        return new JdbcSession(this.db)
            .sql("SELECT id FROM realm")
            .select(new ListOutcome<Realm>(this.realmMapping));
    }

    @Override
    public int count() throws SQLException {
       return new JdbcSession(this.db)
               .sql("SELECT COUNT(*) FROM realm")
               .select(new Outcome<Integer>() {
                    @Override
                    public Integer handle(
                        final ResultSet rs,
                        final Statement stmt
                    ) throws SQLException {
                        int res = 0;
                        if (rs.next()) {
                            res = rs.getInt(1);
                        }
                        return res;
                    }
                }
           );
    }
}
