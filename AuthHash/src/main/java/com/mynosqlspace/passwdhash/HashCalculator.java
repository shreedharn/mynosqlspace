package com.mynosqlspace.passwdhash;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * Created with IntelliJ IDEA.
 * @author: Shreedhar Natarajan
 */
public class HashCalculator {

    private static final String stringFormat = "%02x";
    private String byteArray2Hex(final byte[] hash) {
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format(stringFormat, b);
        }
        return formatter.toString();
    }

    public byte[] getDigest (final byte[] bytesOfMessage, final String hashAlg) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance(hashAlg);
        return md.digest(bytesOfMessage);
    }
    public String getDigestString (final byte[] bytesOfMessage, final String hashAlg) throws NoSuchAlgorithmException {
        return byteArray2Hex(getDigest(bytesOfMessage,hashAlg));
    }
    public byte[] getUtF8BytesOfText(final String str) throws UnsupportedEncodingException {
        return str.getBytes("UTF-8");
    }

}
