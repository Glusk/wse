package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6IT {
    ByteOrder order = ByteOrder.LITTLE_ENDIAN;
    
    SRP6Integer N = 
        new SRP6PrecomputedValue(
            new BigInteger(
                ("AC903A4E 02EEA129 AF182912 72F6AF74" +
                 "6852AB3F 0107FD6A A6A6EB9B CFBBF1E4 7B").replaceAll(" ", ""),
                16
            ),
            order
        );
    
    SRP6Integer g = new SRP6PrecomputedValue(new BigInteger("2"), order);
    
    int pad = N.bytes().length;

    @Test
    public void testSRP6Protocol() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        SecureRandom rng = new SecureRandom();
        
        Mapping<BigInteger, SRP6Integer> intPadRule = 
            new SRP6FromBigIntRule(pad, order);
        Mapping<byte[], SRP6Integer> shaPadRule = 
            new SRP6FromRawRule(20, order);
        
        // Alice registers with Bob - creates a record of the form <I, s, v>
        // --------------------------------------------------------------------
        String I = "Alice";
        String P = "lkji2";
        SRP6Integer s = new SRP6PrecomputedValue(rng.generateSeed(pad), order);
        SRP6Integer x = new SRP6PrivateKey(imd, s, I, P, shaPadRule);
        SRP6Integer v = new SRP6Verifier(N, g, x, intPadRule);
        // --------------------------------------------------------------------

        // Alice sends her username to Bob on login and he looks up her record.
        // He replies with B:
        SRP6Integer b = new SRP6PrecomputedValue(rng.generateSeed(pad), order);
        SRP6Integer B = new SRP6SrvPubEphVal(N, g, v, b, intPadRule);
        // --------------------------------------------------------------------
        
        // Alice can now compute the session key:
        SRP6Integer a = new SRP6PrecomputedValue(rng.generateSeed(pad), order);
        SRP6Integer A = new SRP6CltPubEphVal(N, g, a, intPadRule);
        SRP6Integer u = new SRP6ScrPar(imd, A, B, shaPadRule);
        DigestArgument client_K =
            new SRP6HashedSesKey(
                imd,
                new SRP6CltSesKey(N, g, x, u, a, B, intPadRule)
            );
        //---------------------------------------------------------------------
        
        // Now Bob computes the session key:
        DigestArgument server_K =
            new SRP6HashedSesKey(
                imd,
                new SRP6SrvSesKey(N, A, v, u, b, intPadRule)
            );

        Assert.assertArrayEquals(
            "Keys don't match!", 
            client_K.bytes(), 
            server_K.bytes()
        );
    }
}
