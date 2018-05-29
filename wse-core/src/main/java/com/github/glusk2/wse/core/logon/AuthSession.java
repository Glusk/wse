package com.github.glusk2.wse.core.logon;

import java.nio.channels.SocketChannel;
import java.util.Properties;

import javax.sql.DataSource;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.net.SocketChannelIncomingPacket;
import com.github.glusk2.wse.common.util.Mapping;
import com.github.glusk2.wse.core.db.FakeRecord;
import com.github.glusk2.wse.core.db.MySqlRealms;
import com.github.glusk2.wse.core.db.MySqlRecord;
import com.github.glusk2.wse.core.db.MySqlSession;
import com.github.glusk2.wse.core.db.Realms;
import com.github.glusk2.wse.core.db.Session;
import com.github.glusk2.wse.core.logon.auth.ClientAuthChallengeHeader;
import com.github.glusk2.wse.core.logon.auth.ReferenceCACH;

public final class AuthSession implements Runnable {

    private static final int HEADER_LENGTH = 4;

    private final SocketChannel sc;
    private final ClientAuthChallengeHeader cch;
    private final ImmutableMessageDigest imd;
    private final Mapping<String, SRP6Record> records;
    private final Mapping<String, Session> sessions;
    private final Realms realms;

    public AuthSession(
        SocketChannel sc,
        DataSource db,
        ImmutableMessageDigest imd,
        Properties wseProps
    ) {
        this(
            sc,
            imd,
            new Mapping<String, SRP6Record>() {
                public SRP6Record map(final String identity) {
                    return
                        new MySqlRecord(
                            db,
                            identity,
                            new FakeRecord(
                                imd,
                                new DigestArgument.BYTES(
                                    wseProps.getProperty("fakeRecordSecret")
                                ),
                                identity
                            )
                        );
                }
            },
            new Mapping<String, Session>() {
                public Session map(final String identity) {
                    return new MySqlSession(db, identity);
                }
            },
            new MySqlRealms(db),
            new ReferenceCACH(
                new SocketChannelIncomingPacket(sc, HEADER_LENGTH)
            )
        );
    }

    public AuthSession(
        SocketChannel sc,
        ImmutableMessageDigest imd,
        Mapping<String, SRP6Record> records,
        Mapping<String, Session> sessions,
        Realms realms,
        ClientAuthChallengeHeader cch
    ) {
        this.sc = sc;
        this.imd = imd;
        this.records = records;
        this.sessions = sessions;
        this.realms = realms;
        this.cch = cch;
    }

    @Override
    public void run() {
        try {
            if (cch.opcode() == 0) {
                new AuthLogon(
                    sc,
                    imd,
                    records,
                    sessions,
                    realms,
                    cch.size(),
                    cch.version()
                ).run();
            } else if (cch.opcode() == 2) {
                new AuthReconnect(
                    sc,
                    imd,
                    sessions,
                    realms,
                    cch.size(),
                    cch.version()
                ).run();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error in Auth Session!", e);
        }
    }
}
