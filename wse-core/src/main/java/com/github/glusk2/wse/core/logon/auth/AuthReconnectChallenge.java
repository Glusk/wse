package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.net.Response;

public interface AuthReconnectChallenge extends Response {
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
    DigestArgument serverSalt();
}
