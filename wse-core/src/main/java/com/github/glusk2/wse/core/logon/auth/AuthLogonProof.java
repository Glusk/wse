package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Arrays;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.net.Response;

public interface AuthLogonProof extends Response {
    /** SRP-6 variable A. */
    SRP6Integer cltPubEphVal() throws IOException;
    /** SRP-6 variable M1, sent by the client. */
    DigestArgument cltSesProof() throws IOException;
    /** SRP-6 variable M1, computed server-side. */
    DigestArgument cltSesProofRef() throws SQLException, IOException;
    default boolean isClientProofValid() throws SQLException, IOException {
        return Arrays.equals(cltSesProof().bytes(), cltSesProofRef().bytes());
    }
    /** SRP-6 variable M2. */
    DigestArgument srvSesProof() throws IOException, SQLException;
    /** SRP-6 variable K. */
    DigestArgument sessionKey() throws SQLException, IOException;
}
