package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;

public interface ClientAuthChallengeHeader {
    /**
     * Returns Grunt Challenge Opcode.
     *
     * @throws IOException
     *         If an I/O error occurs while reading {@code this} header
     *         (e.g. if a client disconnects).
     */
    byte opcode() throws IOException;

    /**
     * Returns Grunt protocol version byte.
     *
     * @throws IOException
     *         If an I/O error occurs while reading {@code this} header
     *         (e.g. if a client disconnects).
     */
    byte version() throws IOException;

    /**
     * Returns a positive number of remaining payload bytes for the packet that
     * this header belongs to.
     *
     * @throws IOException
     *         If an I/O error occurs while reading {@code this} header
     *         (e.g. if a client disconnects).
     */
    int size() throws IOException;
}
