package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_A;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_N;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_S;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_b;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_u;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_v;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6ServerSecretTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new RFC5054TestVector_N().bytes().length,
                ByteOrder.BIG_ENDIAN
            );

        assertTrue(
            "Computed value doesn't match the test vector.",
            new RFC5054TestVector_S().string().equals(
                new SRP6ServerSecret(
                    new RFC5054TestVector_N(),
                    new RFC5054TestVector_A(),
                    new RFC5054TestVector_v(),
                    new RFC5054TestVector_u(),
                    new RFC5054TestVector_b(),
                    rule
                ).string()
            )
        );
    }
}
