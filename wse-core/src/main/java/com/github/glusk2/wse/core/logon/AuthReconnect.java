package com.github.glusk2.wse.core.logon;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.net.OutgoingPacket;
import com.github.glusk2.wse.common.net.SocketChannelIncomingPacket;
import com.github.glusk2.wse.common.net.SocketChannelOutgoingPacket;
import com.github.glusk2.wse.common.util.Mapping;
import com.github.glusk2.wse.core.db.Realms;
import com.github.glusk2.wse.core.db.Session;
import com.github.glusk2.wse.core.logon.auth.AuthReconnectChallenge;
import com.github.glusk2.wse.core.logon.auth.AuthReconnectProof;
import com.github.glusk2.wse.core.logon.auth.ReferenceARC;
import com.github.glusk2.wse.core.logon.auth.ReferenceARP;

public final class AuthReconnect implements Runnable {

    private static final int CLIENT_RECONNECT_PROOF_LENGTH = 58;
    private final AuthReconnectChallenge challenge;
    private final AuthReconnectProof proof;
    private final Mapping<ByteBuffer, OutgoingPacket> outPackets;
    private final Realms realms;
    private final SocketChannel sc;

    public AuthReconnect(
        SocketChannel sc,
        ImmutableMessageDigest imd,
        Mapping<String, Session> sessions,
        Realms realms,
        int challengeSize,
        byte gruntVersion
    ) {
        this(
            sc,
            new ReferenceARC(
                new SocketChannelIncomingPacket(sc, challengeSize)
            ),
            imd,
            sessions,
            realms,
            gruntVersion
        );
    }

    public AuthReconnect(
        SocketChannel sc,
        AuthReconnectChallenge challenge,
        ImmutableMessageDigest imd,
        Mapping<String, Session> sessions,
        Realms realms,
        byte gruntVersion
    ) {
        this(
            sc,
            challenge,
            new ReferenceARP(
                gruntVersion,
                challenge,
                new SocketChannelIncomingPacket(
                    sc,
                    CLIENT_RECONNECT_PROOF_LENGTH
                ),
                imd,
                sessions
            ),
            new Mapping<ByteBuffer, OutgoingPacket>() {
                @Override
                public OutgoingPacket map(final ByteBuffer key) {
                    return new SocketChannelOutgoingPacket(sc, key);
                }
            },
            realms
        );
    }

    public AuthReconnect(
        SocketChannel sc,
        AuthReconnectChallenge challenge,
        AuthReconnectProof proof,
        Mapping<ByteBuffer, OutgoingPacket> outPackets,
        Realms realms
    ) {
        this.sc = sc;
        this.challenge = challenge;
        this.proof = proof;
        this.outPackets = outPackets;
        this.realms = realms;
    }

    @Override
    public void run() {
        try {
            //dummy read -> triggers reading of the client's
            //Auth Reconnect Challenge -> it contains no data necessary
            //for server's immediate reply but needs to be read nonetheless
            challenge.identity();

            outPackets.map(challenge.response()).sendFull();
            outPackets.map(proof.response()).sendFull();

            if (proof.isClientProofValid()) {
                new RealmList(
                    sc,
                    outPackets,
                    realms,
                    challenge.identity()
                ).run();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error in Auth Reconnect!", e);
        }
    }
}
