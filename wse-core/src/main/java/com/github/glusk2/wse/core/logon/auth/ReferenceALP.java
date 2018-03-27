package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.SQLException;

import com.github.glusk2.wse.common.crypto.srp6.SRP6CltSesProof;
import com.github.glusk2.wse.common.crypto.srp6.SRP6FromBigIntRule;
import com.github.glusk2.wse.common.crypto.srp6.SRP6FromRawRule;
import com.github.glusk2.wse.common.crypto.srp6.SRP6SessionKey;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6ScrPar;
import com.github.glusk2.wse.common.crypto.srp6.SRP6ServerSecret;
import com.github.glusk2.wse.common.crypto.srp6.SRP6SrvSesProof;
import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.net.IncomingPacket;
import com.github.glusk2.wse.common.util.Mapping;

/**
 * A reference Authentication Logon Proof implementation.
 */
public final class ReferenceALP implements AuthLogonProof {

    private static final byte OPCODE = 1;
    private static final byte LOGIN_OK = 0x00;
    private static final byte LOGIN_UNKNOWN_ACCOUNT = 0x04;
    private static final byte LOGIN_INCORRECT_PASSWORD = 0x05;
    private static final byte LOGIN_BADVERSION = 0x09;
    private static final byte GRUNT_WOTLK = 8;
    private static final int GAMEACCOUNT_FLAG_PROPASS = 0x00800000;
    private static final int INT_PAD_LENGTH = 32;
    private static final int SHA1_LENGTH = 20;

    private final byte gruntVersion;
    private final AuthLogonChallenge challenge;
    private final IncomingPacket clientProof;
    private final ImmutableMessageDigest imd;
    private final Mapping<byte[], SRP6Integer> biRule;

    public ReferenceALP(
        byte gruntVersion,
        AuthLogonChallenge challenge,
        IncomingPacket clientProof,
        ImmutableMessageDigest imd
    ) {
        this(
            gruntVersion,
            challenge,
            clientProof,
            imd,
            new SRP6FromRawRule(INT_PAD_LENGTH, ByteOrder.LITTLE_ENDIAN)
        );
    }

    public ReferenceALP(
        byte gruntVersion,
        AuthLogonChallenge challenge,
        IncomingPacket clientProof,
        ImmutableMessageDigest imd,
        Mapping<byte[], SRP6Integer> biRule
    ) {
        this.gruntVersion = gruntVersion;
        this.challenge = challenge;
        this.clientProof = clientProof;
        this.imd = imd;
        this.biRule = biRule;
    }

    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    public SRP6Integer cltPubEphVal() throws IOException {
        byte[] A = new byte[INT_PAD_LENGTH];
        ByteBuffer buf = (ByteBuffer) clientProof.buffer().position(1);
        buf.get(A);
        return biRule.map(A);
    }

    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    public DigestArgument cltSesProof() throws IOException {
        byte[] M1 = new byte[SHA1_LENGTH];
        ByteBuffer buf =
            (ByteBuffer) clientProof.buffer().position(1 + INT_PAD_LENGTH);
        buf.get(M1);
        return new DigestArgument.BYTES(M1);
    }

    @Override
    public DigestArgument cltSesProofRef() throws SQLException, IOException {
        return
            new SRP6CltSesProof(
                imd,
                challenge.record().modulus(),
                challenge.record().generator(),
                challenge.identity(),
                challenge.record().salt(),
                cltPubEphVal(),
                challenge.srvPubEphVal(),
                sessionKey()
            );
    }

    @Override
    @SuppressWarnings("checkstyle:localvariablename")
    public boolean isClientProofValid() throws SQLException, IOException {
        BigInteger N = challenge.record().modulus().bigInteger();
        BigInteger A = cltPubEphVal().bigInteger();
        return
            !A.mod(N).equals(BigInteger.ZERO) &&
            AuthLogonProof.super.isClientProofValid();
    }

    @Override
    public DigestArgument srvSesProof() throws IOException, SQLException {
        return
            new SRP6SrvSesProof(
                imd,
                cltPubEphVal(),
                cltSesProof(),
                sessionKey()
            );
    }

    @Override
    public DigestArgument sessionKey() throws SQLException, IOException {
        return
            new SRP6SessionKey(
                imd,
                new SRP6ServerSecret(
                    challenge.record().modulus(),
                    cltPubEphVal(),
                    challenge.record().verifier(),
                    new SRP6ScrPar(
                        imd,
                        cltPubEphVal(),
                        challenge.srvPubEphVal(),
                        new SRP6FromRawRule(
                            SHA1_LENGTH,
                            ByteOrder.LITTLE_ENDIAN
                        )
                    ),
                    challenge.srvPrvEphVal(),
                    new SRP6FromBigIntRule(
                        INT_PAD_LENGTH,
                        ByteOrder.LITTLE_ENDIAN
                    )
                )
            );
    }

    @Override
    public ByteBuffer response() throws Exception {
        if (gruntVersion < GRUNT_WOTLK) {
            ByteBuffer packet = ByteBuffer.allocate(1 + 1);
            packet.put(OPCODE);
            packet.put(LOGIN_BADVERSION);
            return (ByteBuffer) packet.flip();
        }
        if (!isClientProofValid()) {
            ByteBuffer packet = ByteBuffer.allocate(1 + 1);
            packet.put(OPCODE);
            packet.put(
                (byte) (LOGIN_UNKNOWN_ACCOUNT | LOGIN_INCORRECT_PASSWORD)
            );
            return (ByteBuffer) packet.flip();
        }

        ByteBuffer packet =
            ByteBuffer.allocate(
                1 + 1 + SHA1_LENGTH + 2 * Integer.BYTES + Short.BYTES
            ).order(ByteOrder.LITTLE_ENDIAN);
        packet.put(OPCODE);
        packet.put(LOGIN_OK);
        packet.put(srvSesProof().bytes());
        packet.putInt(GAMEACCOUNT_FLAG_PROPASS);
        // HW survey ID: 0 -> disabled
        packet.putInt(0);
        // flags: 0x0001 -> AccountMessagesAvailable
        packet.putShort((short) 0);
        return (ByteBuffer) packet.flip();
    }

}
