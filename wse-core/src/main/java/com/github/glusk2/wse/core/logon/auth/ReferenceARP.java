package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.SQLException;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.IntermediateDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;
import com.github.glusk2.wse.common.net.IncomingPacket;
import com.github.glusk2.wse.common.util.Mapping;
import com.github.glusk2.wse.core.db.Session;

/**
 * A reference Authentication Reconnect Proof implementation.
 */
public final class ReferenceARP implements AuthReconnectProof {

    private static final byte OPCODE = 3;
    private static final byte LOGIN_OK = 0x00;
    private static final byte LOGIN_UNKNOWN_ACCOUNT = 0x04;
    private static final byte LOGIN_INCORRECT_PASSWORD = 0x05;
    private static final byte GRUNT_WOTLK = 8;
    private static final int SALT_LENGTH = 16;
    private static final int SHA1_LENGTH = 20;

    private final byte gruntVersion;
    private final AuthReconnectChallenge challenge;
    private final IncomingPacket clientReconnectProof;
    private final ImmutableMessageDigest imd;
    private final Mapping<String, Session> sessions;

    public ReferenceARP(
        byte gruntVersion,
        AuthReconnectChallenge challenge,
        IncomingPacket clientReconnectProof,
        ImmutableMessageDigest imd,
        Mapping<String, Session> sessions
    ) {
        this.gruntVersion = gruntVersion;
        this.challenge = challenge;
        this.clientReconnectProof = clientReconnectProof;
        this.imd = imd;
        this.sessions = sessions;
    }

    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    public DigestArgument clientSalt() throws IOException {
        byte[] R1 = new byte[SALT_LENGTH];
        ByteBuffer buf =
            (ByteBuffer) clientReconnectProof.buffer().position(1);
        buf.get(R1);
        return new DigestArgument.BYTES(R1);
    }

    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    public DigestArgument reconnectProof() throws IOException {
        byte[] R2 = new byte[SHA1_LENGTH];
        ByteBuffer buf = (ByteBuffer) clientReconnectProof
            .buffer()
            .position(1 + SALT_LENGTH);
        buf.get(R2);
        return new DigestArgument.BYTES(R2);
    }

    @Override
    public DigestArgument reconnectProofRef()
        throws SQLException, IOException {
        return
            new IntermediateDigest(
                imd,
                new StringArgument(challenge.identity()),
                clientSalt(),
                challenge.serverSalt(),
                sessionKey()
            );
    }

    @Override
    public DigestArgument sessionKey() throws SQLException, IOException {
        return
            new DigestArgument.BYTES(
                sessions.map(
                    challenge.identity()
                ).key()
            );
    }

    @Override
    public ByteBuffer response() throws Exception {
        if (!isClientProofValid()) {
            return (ByteBuffer) ByteBuffer
                .allocate(1 + 1)
                .put(OPCODE)
                .put((byte) (LOGIN_UNKNOWN_ACCOUNT | LOGIN_INCORRECT_PASSWORD))
                .flip();
        }
        if (gruntVersion >= GRUNT_WOTLK) {
            return (ByteBuffer) ByteBuffer
                .allocate(1 + 1 + 2)
                .put(OPCODE)
                .put(LOGIN_OK)
                .putShort((short) 0) //unknown
                .flip();
        }
        return (ByteBuffer) ByteBuffer
            .allocate(1 + 1)
            .put(OPCODE)
            .put(LOGIN_OK)
            .flip();
    }
}
