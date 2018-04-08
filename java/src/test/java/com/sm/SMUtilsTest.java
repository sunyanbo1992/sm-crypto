package com.sm;

import org.testng.annotations.Test;

import java.math.BigInteger;

import static org.testng.Assert.assertEquals;

public class SMUtilsTest {

    @Test
    public void intToBytesTest() throws Exception {
        byte[] actual = SMUtils.intToBytes(1);
        byte[] expect = {0x01,0x00,0x00,0x00};
        assertEquals(actual,expect);
    }

    @Test
    public void byteToIntTest() throws Exception {
        byte[] bytes = {0x01,0x00,0x00,0x00};
        int actual = SMUtils.byteToInt(bytes);
        int expect = 1;
        assertEquals(actual,expect);
    }

    @Test
    public void longToBytesTest() throws Exception {
        long data = 1L;
        byte[] actual = SMUtils.longToBytes(data);
        byte[] expect = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        assertEquals(actual,expect);

    }

    @Test
    public void byteConvert32BytesTest() throws Exception {
        byte[] bytes = {0x01,0x00,0x00,0x00};
        BigInteger data = new BigInteger(bytes);
        byte[] actual = SMUtils.byteConvert32Bytes(data);
        byte[] expect = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
        assertEquals(actual, expect);
    }

    @Test
    public void byteConvertIntegerTest() throws Exception {
        byte[] data = {0x01,0x00,0x00,0x00};
        BigInteger actual = SMUtils.byteConvertInteger(data);
        BigInteger expect = new BigInteger(data);
        assertEquals(actual, expect);
    }

    @Test
    public void getHexStringTest() throws Exception {

        byte[] data = {0x01,0x00,0x00,0x00};
        String actual = SMUtils.getHexString(data);
        String expect = "01000000";
        assertEquals(actual, expect);

    }


    @Test
    public void hexStringToBytesTest() throws Exception {

        String data = "01000000";
        byte[] actual = SMUtils.hexStringToBytes(data);
        byte[] expect = {0x01,0x00,0x00,0x00};
        assertEquals(actual, expect);
    }

    @Test
    public void charToByteTest() throws Exception {
        char data = '1';
        byte actual = SMUtils.charToByte(data);
        byte expect = 1;
        assertEquals(actual, expect);

    }

    @Test
    public void encodeHexTest() throws Exception {
        byte[] data = {0x00, 0x00, 0x00, 0x01};
        char[] actual = SMUtils.encodeHex(data);
        char[] expect = {'0', '0', '0', '0', '0', '0', '0', '1'};
        assertEquals(actual, expect);

    }

    @Test
    public void encodeHexStringTest() throws Exception {

        byte[] data = {0x00, 0x00, 0x00, 0x01};
        String actual = SMUtils.encodeHexString(data);
        String expect = "00000001";
        assertEquals(actual, expect);

    }


    @Test
    public void decodeHexTest() throws Exception {
        char[] data = {'0', '0', '0', '0', '0', '0', '0', '1'};
        byte[] expect = {0x00, 0x00, 0x00, 0x01};
        byte[] actual = SMUtils.decodeHex(data);
        assertEquals(actual, expect);
    }

    @Test
    public void toDigitTest() throws Exception {
        char data = 'F';
        int index = 0 ;
        int actual = SMUtils.toDigit(data, index);
        int expect = 15;
        assertEquals(actual, expect);
    }


    @Test
    public void hexToByteTest() throws Exception {
        String data = "00000001";
        byte[] actual = SMUtils.hexToByte(data);
        byte[] expect = {0x00,0x00,0x00,0x01};
        assertEquals(actual, expect);

    }

    @Test
    public void byteToHexTest() throws Exception {

        byte[] data = {0x00,0x00,0x00,0x01};
        String actual = SMUtils.byteToHex(data);
        String expect = "00000001";
        assertEquals(actual, expect);

    }

    @Test
    public void decodeBase64Test() throws Exception {
        String data = "ZQsVICALFg==";
        byte[] actual = SMUtils.decodeBase64(data);
        byte[] expect = {101,11,21,32,32,11,22};
        assertEquals(actual, expect);
    }

    @Test
    public void encodeBase64Test() throws Exception {

        byte[] data = {101,11,21,32,32,11,22};
        String actual = SMUtils.encodeBase64(data);
        String expect = "ZQsVICALFg==";
        assertEquals(actual, expect);
    }

    @Test
    public void intToByteArrayTest() throws Exception {
        int data = 1;
        byte[] actual = SMUtils.intToByteArray(data);
        byte[] expect = {0x00,0x00,0x00,0x01};
        assertEquals(actual, expect);
    }


    @Test
    public void hexToBase64Test() throws Exception {
        String hex = "e5958a";
        String actual = SMUtils.hexToBase64(hex);
        String expect = "5ZWK";
        assertEquals(actual, expect);

    }
}