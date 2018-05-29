package com.github.glusk2.wse.core.logon;

import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.security.MessageDigest;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public final class LogonServer implements Runnable {

    private static final short DEFAULT_PORT = 3724;
    private static final int NUM_PROCESSORS =
        Runtime.getRuntime().availableProcessors();

    private final InetSocketAddress ip;
    private final ExecutorService threadPool;
    private final DataSource ds;
    private final Properties wseProps;
    private final ImmutableMessageDigest imd;

    public LogonServer(
        InetAddress ia,
        int port,
        DataSource ds,
        Properties wseProps,
        ImmutableMessageDigest imd
    ) {
        this(
            new InetSocketAddress(ia, port),
            new ThreadPoolExecutor(
                NUM_PROCESSORS,
                NUM_PROCESSORS * 2,
                1,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(NUM_PROCESSORS * 2 * 2)
            ),
            ds,
            wseProps,
            imd
        );
    }

    public LogonServer(
        InetSocketAddress ip,
        ExecutorService threadPool,
        DataSource ds,
        Properties wseProps,
        ImmutableMessageDigest imd
    ) {
        this.ip = ip;
        this.threadPool = threadPool;
        this.ds = ds;
        this.wseProps = wseProps;
        this.imd = imd;
    }

    @Override
    public void run() {
        try (ServerSocketChannel ssc = ServerSocketChannel.open().bind(ip)) {
            while (true) {
                // Accept a new connection and handle it in a new thread:
                threadPool.execute(
                    new AuthSession(ssc.accept(), ds, imd, wseProps)
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Server crashed!", e);
        }
    }

    public static void main(final String[] args) throws Exception {
        Properties hikariProps = new Properties();
        Properties wseProps = new Properties();

        String hikariConfFileName = System.getProperty("hikariConfig");
        if (hikariConfFileName == null) {
            hikariConfFileName = "/hikari.properties";
        }
        String wseConfFileName = System.getProperty("wseConfig");
        if (wseConfFileName == null) {
            wseConfFileName = "/wse.properties";
        }

        try (
            InputStream hikari =
                LogonServer.class.getResourceAsStream(
                    hikariConfFileName);
            InputStream wse =
                LogonServer.class.getResourceAsStream(
                    wseConfFileName)
        ) {
            hikariProps.load(hikari);
            wseProps.load(wse);
        }

        new LogonServer(
            Inet4Address.getByName("localhost"),
            DEFAULT_PORT,
            new HikariDataSource(
                new HikariConfig(
                    hikariProps
                )
            ),
            wseProps,
            new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"))
        ).run();
    }
}
