package com.sm.sm4;

import com.sm.SMUtils;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class SM4EncryptTest {

    @Test
    public void encryptSM4Test() throws Exception {

        byte[] key = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab,
                (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc,
                (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10 };

        byte[] sourceData = {
                (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab, (byte)0xcd, (byte) 0xef,
                (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte)0x32, (byte)0x10
        };
        byte[] actual = SM4Encrypt.encryptSM4(sourceData, key);
        String expect1 = "681edf34d206965e86b3e94f536e4246".toUpperCase();
        assertEquals(SMUtils.byteToHex(actual),expect1);
        for (int i = 0 ;i < 1000000; ++i ){
            sourceData = SM4Encrypt.encryptSM4(sourceData, key);
        }
        String expect2 = "595298c7c6fd271f0402f804c33d3f66".toUpperCase();
        assertEquals(SMUtils.byteToHex(sourceData),expect2);

    }

}