package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_B;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_N;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_b;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_g;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_k;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_v;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6SrvPubEphVaLTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new RFC5054TestVector_N().bytes().length,
                ByteOrder.BIG_ENDIAN
            );

        assertTrue(
            "Computed value doesn't match the test vector.",
            new RFC5054TestVector_B().string().equals(
                new SRP6SrvPubEphVal(
                    new RFC5054TestVector_N(),
                    new RFC5054TestVector_g(),
                    new RFC5054TestVector_k(),
                    new RFC5054TestVector_v(),
                    new RFC5054TestVector_b(),
                    rule
                ).string()
            )
        );
    }
}
