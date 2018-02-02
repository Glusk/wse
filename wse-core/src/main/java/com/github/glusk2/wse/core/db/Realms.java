package com.github.glusk2.wse.core.db;

import java.sql.SQLException;

public interface Realms {
    int count() throws SQLException;
    Iterable<Realm> iterate() throws SQLException;
}
