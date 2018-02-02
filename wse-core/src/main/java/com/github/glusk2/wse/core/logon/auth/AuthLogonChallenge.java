package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.sql.SQLException;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.net.Response;

public interface AuthLogonChallenge extends Response {
    /**
     * Returns the SRP6 identity field ({@code I}), read from the client's
     * challenge. This is the player's account username that was used to log-in
     * with.
     *
     * @returns  SRP6 identity field ({@code I})
     * @throws IOException
     *         If an I/O error occurs (e.g. if a client disconnects).
     */
    String identity() throws IOException;
    /** SRP-6 record under key {@link #identity()} -> <v, s, N, g>. */
    SRP6Record record() throws IOException;
    /** SRP-6 variable b. */
    SRP6Integer srvPrvEphVal();
    /** SRP-6 variable B. */
    SRP6Integer srvPubEphVal() throws SQLException, IOException;
}
