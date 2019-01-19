package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcN;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcG;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcV;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcX;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6VerifierTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new TestVectorUcN().bytes().length,
                ByteOrder.BIG_ENDIAN
            );

        assertTrue(
            new TestVectorLcV().string().equals(
                new SRP6Verifier(
                    new TestVectorUcN(),
                    new TestVectorLcG(),
                    new TestVectorLcX(),
                    rule
                ).string()
            )
        );
    }
}
