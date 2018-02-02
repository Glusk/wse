package com.github.glusk2.wse.core.logon.auth;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Arrays;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.net.Response;

public interface AuthReconnectProof extends Response {
    /** R1. */
    DigestArgument clientSalt() throws IOException;
    /** R2 sent by the client. */
    DigestArgument reconnectProof() throws IOException;
    /** R2 computed server-side. */
    DigestArgument reconnectProofRef() throws SQLException, IOException;
    default boolean isClientProofValid() throws IOException, SQLException {
        return
            Arrays.equals(
                reconnectProof().bytes(),
                reconnectProofRef().bytes()
            );
    }
    /** SRP-6 variable K. */
    DigestArgument sessionKey() throws SQLException, IOException;
}
