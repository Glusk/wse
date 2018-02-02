package com.github.glusk2.wse.core.logon;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import com.github.glusk2.wse.common.net.OutgoingPacket;
import com.github.glusk2.wse.common.net.Response;
import com.github.glusk2.wse.common.net.SocketChannelIncomingPacket;
import com.github.glusk2.wse.common.util.Mapping;
import com.github.glusk2.wse.core.db.Realms;
import com.github.glusk2.wse.core.logon.auth.ServerRealmList;

public final class RealmList implements Runnable {

    private static final int REQUEST_SIZE = 5;

    private final SocketChannel sc;
    private final Mapping<ByteBuffer, OutgoingPacket> outPackets;
    private final Response realmList;

    public RealmList(
        SocketChannel sc,
        Mapping<ByteBuffer, OutgoingPacket> outPackets,
        Realms realms,
        String accountName
    ) {
        this(
            sc,
            outPackets,
            new ServerRealmList(
                realms,
                accountName
            )
        );
    }
    public RealmList(
        SocketChannel sc,
        Mapping<ByteBuffer, OutgoingPacket> outPackets,
        Response realmList
    ) {
        this.sc = sc;
        this.outPackets = outPackets;
        this.realmList = realmList;
    }

    @Override
    public void run() {
        while (true) {
            try {
                // dummy read the request - discard the bytes read
                if (
                    new SocketChannelIncomingPacket(sc, REQUEST_SIZE)
                        .buffer()
                        .hasRemaining()
                ) {
                    return;
                }
                outPackets.map(realmList.response()).sendFull();
            } catch (Exception e) {
                throw new RuntimeException("Error in Realm List!", e);
            }
        }
    }
}
