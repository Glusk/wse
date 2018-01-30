package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_A;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_N;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_a;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_g;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6CltPubEphlValTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new RFC5054TestVector_N().bytes().length,
                ByteOrder.BIG_ENDIAN
            );
        
        assertTrue(
            "Computed value doesn't match the test vector.",
            new RFC5054TestVector_A().string().equals(
                new SRP6CltPubEphVal(
                    new RFC5054TestVector_N(),
                    new RFC5054TestVector_g(),
                    new RFC5054TestVector_a(),
                    rule
                ).string()
            )
        );
    }
}
