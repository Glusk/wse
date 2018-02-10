package com.github.glusk2.wse.core.logon.auth;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.net.Response;
import com.github.glusk2.wse.core.db.Realm;
import com.github.glusk2.wse.core.db.Realms;

public final class ServerRealmList implements Response {

    private static final byte OPCODE = 0x10;
    private static final byte REALM_FLAG_SPECIFYBUILD = 1 << 2;
    private static final int MAX_REALM_LENGTH = 256;
    private static final int MAX_REALMS_LENGTH = 100 * MAX_REALM_LENGTH;

    private final Realms realms;
    private final String username;

    public ServerRealmList(Realms realms, String username) {
        this.realms = realms;
        this.username = username;
    }

    @Override
    @SuppressWarnings("checkstyle:avoidinlineconditionals")
    public ByteBuffer response() throws Exception {
        ByteBuffer realmsBuf =
            ByteBuffer
                .allocate(MAX_REALMS_LENGTH)
                .order(ByteOrder.LITTLE_ENDIAN);

        for (Realm realm : realms.iterate()) {
            ByteBuffer realmBuf =
                ByteBuffer
                    .allocate(MAX_REALM_LENGTH)
                    .order(ByteOrder.LITTLE_ENDIAN);

            realmBuf.put(realm.type());
            realmBuf.put((byte) (realm.isLocked() ? 1 : 0));
            realmBuf.put(realm.flags());
            realmBuf.put(realm.name().bytes());
            realmBuf.put(realm.address().bytes());
            realmBuf.putFloat(realm.population());
            realmBuf.put(realm.characterCount(username));
            realmBuf.put(realm.location());
            realmBuf.put((byte) realm.id());
            if ((realm.flags() & REALM_FLAG_SPECIFYBUILD) != 0) {
                realmBuf.put(realm.build());
            }

            realmsBuf.put((ByteBuffer) realmBuf.flip());
        }

        return (ByteBuffer) ByteBuffer
            .allocate(
                1 + Short.BYTES + Integer.BYTES + Integer.BYTES + Short.BYTES +
                MAX_REALMS_LENGTH + Short.BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(OPCODE)
            .putShort((short) (Integer.BYTES + Short.BYTES +
                realmsBuf.position() + Short.BYTES))
            .putInt(0x00000000) //unknown
            .putShort((short) realms.count())
            .put((ByteBuffer) realmsBuf.flip())
            .putShort((short) 0x0000) //unknown
            .flip();
    }

}
