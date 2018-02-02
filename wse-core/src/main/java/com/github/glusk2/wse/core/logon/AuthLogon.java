package com.github.glusk2.wse.core.logon;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.net.OutgoingPacket;
import com.github.glusk2.wse.common.net.SocketChannelIncomingPacket;
import com.github.glusk2.wse.common.net.SocketChannelOutgoingPacket;
import com.github.glusk2.wse.common.util.Mapping;
import com.github.glusk2.wse.core.db.Realms;
import com.github.glusk2.wse.core.db.Session;
import com.github.glusk2.wse.core.logon.auth.AuthLogonChallenge;
import com.github.glusk2.wse.core.logon.auth.AuthLogonProof;
import com.github.glusk2.wse.core.logon.auth.ReferenceALC;
import com.github.glusk2.wse.core.logon.auth.ReferenceALP;

public final class AuthLogon implements Runnable {

    private static final int CLIENT_LOGON_PROOF_LENGTH = 75;

    private final AuthLogonChallenge challenge;
    private final AuthLogonProof proof;
    private final Mapping<ByteBuffer, OutgoingPacket> outPackets;
    private final Mapping<String, Session> sessions;
    private final Realms realms;
    private final SocketChannel sc;

    public AuthLogon(
        SocketChannel sc,
        ImmutableMessageDigest imd,
        Mapping<String, SRP6Record> records,
        Mapping<String, Session> sessions,
        Realms realms,
        int challengeSize,
        byte gruntVersion
    ) {
        this(
            sc,
            new ReferenceALC(
                new SocketChannelIncomingPacket(sc, challengeSize),
                records
            ),
            imd,
            sessions,
            realms,
            gruntVersion
        );
    }

    public AuthLogon(
        SocketChannel sc,
        AuthLogonChallenge challenge,
        ImmutableMessageDigest imd,
        Mapping<String, Session> sessions,
        Realms realms,
        byte gruntVersion
    ) {
        this(
            sc,
            challenge,
            new ReferenceALP(
                gruntVersion,
                challenge,
                new SocketChannelIncomingPacket(sc, CLIENT_LOGON_PROOF_LENGTH),
                imd
            ),
            new Mapping<ByteBuffer, OutgoingPacket>() {
                @Override
                public OutgoingPacket map(final ByteBuffer key) {
                    return new SocketChannelOutgoingPacket(sc, key);
                }
            },
            sessions,
            realms
        );
    }

    public AuthLogon(
        SocketChannel sc,
        AuthLogonChallenge challenge,
        AuthLogonProof proof,
        Mapping<ByteBuffer, OutgoingPacket> outPackets,
        Mapping<String, Session> sessions,
        Realms realms
    ) {
        this.sc = sc;
        this.challenge = challenge;
        this.proof = proof;
        this.outPackets = outPackets;
        this.sessions = sessions;
        this.realms = realms;
    }

    @Override
    public void run() {
        try {
            outPackets.map(challenge.response()).sendFull();
            outPackets.map(proof.response()).sendFull();

            if (proof.isClientProofValid()) {
                sessions.map(
                    challenge.identity()
                    ).update(
                        proof.sessionKey().bytes()
                    );
                new RealmList(
                    sc,
                    outPackets,
                    realms,
                    challenge.identity()
                ).run();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error in Auth Logon!", e);
        }
    }
}
