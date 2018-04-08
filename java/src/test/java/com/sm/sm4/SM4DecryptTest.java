package com.sm.sm4;

import com.sm.SMUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class SM4DecryptTest {

    @Test
    public void decryptSM4Test() throws Exception {

        String cipherText1 = "681edf34d206965e86b3e94f536e4246";
        byte[] key = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab,
                (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc,
                (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10 };
        byte[] actual1 = SM4Decrypt.decryptSM4(cipherText1, key);
        String expect1 = "0123456789ABCDEFFEDCBA9876543210";
        Assert.assertEquals(SMUtils.byteToHex(actual1), expect1);
        String cipherText2 = "595298c7c6fd271f0402f804c33d3f66";
        byte[] actual2 = SM4Decrypt.decryptSM4(cipherText2, key, 1000000);
        String expect2 = "0123456789ABCDEFFEDCBA9876543210";
        assertEquals(SMUtils.byteToHex(actual2), expect2);

    }
}