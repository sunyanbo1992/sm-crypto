package com.sm.sm3;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SM3 {
    public static final byte[] iv = { 0x73, (byte) 0x80, 0x16, 0x6f, 0x49,
            0x14, (byte) 0xb2, (byte) 0xb9, 0x17, 0x24, 0x42, (byte) 0xd7,
            (byte) 0xda, (byte) 0x8a, 0x06, 0x00, (byte) 0xa9, 0x6f, 0x30,
            (byte) 0xbc, (byte) 0x16, 0x31, 0x38, (byte) 0xaa, (byte) 0xe3,
            (byte) 0x8d, (byte) 0xee, 0x4d, (byte) 0xb0, (byte) 0xfb, 0x0e,
            0x4e };

    private static final byte[] FirstPadding = {(byte) 0x80};
    private static final byte[] ZeroPadding = {(byte) 0x00};
    
    public static int[] Tj = new int[64];

    static {
        for (int i = 0; i < 16; i++) {
            Tj[i] = 0x79cc4519;
        }

        for (int i = 16; i < 64; i++) {
            Tj[i] = 0x7a879d8a;
        }
    }

    private static int FFj(int X, int Y, int Z, int j) {
        if (j >= 0 && j <= 15) {
            return SM3Utils.FF1j(X, Y, Z);
        }
        else {
            return SM3Utils.FF2j(X, Y, Z);
        }
    }

 
    private static int GGj(int X, int Y, int Z, int j) {
        if (j >= 0 && j <= 15) {
            return SM3Utils.GG1j(X, Y, Z);
        }
        else {
            return SM3Utils.GG2j(X, Y, Z);
        }
    }

    private static int P0(int X) {

        int y = SM3Utils.bitCycleLeft(X, 9);
        int z = SM3Utils.bitCycleLeft(X, 17);
        return X ^ y ^ z;
    }

    private static int P1(int X) {

        return X ^ SM3Utils.bitCycleLeft(X, 15) ^ SM3Utils.bitCycleLeft(X, 23);
    }

    public static byte[] padding(byte[] source) throws IOException {

        if (source.length >= 0x2000000000000000l) {
            throw new RuntimeException("src data invalid.");
        }
        long l = source.length * 8;
        long k = 448 - (l + 1) % 512;
        if (k < 0) {
            k = k + 512;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(source);
        out.write(FirstPadding);
        long i = k - 7;
        while (i > 0) {
            out.write(ZeroPadding);
            i -= 8;
        }
        out.write(SM3Utils.long2bytes(l));

        return out.toByteArray();
    }

    private static int[][] expand(int[] B) {

        int W[] = new int[68];
        int W1[] = new int[64];
        System.arraycopy(B, 0, W, 0, B.length);

        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ SM3Utils.bitCycleLeft(W[i - 3], 15))
                    ^ SM3Utils.bitCycleLeft(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; i++) {
            W1[i] = W[i] ^ W[i + 4];
        }

        return new int[][] { W, W1 };
    }

    public static int[] CF(int[] V, int[] B) {
        int a, b, c, d, e, f, g, h;
        int ss1, ss2, tt1, tt2;
        a = V[0];
        b = V[1];
        c = V[2];
        d = V[3];
        e = V[4];
        f = V[5];
        g = V[6];
        h = V[7];

        int[][] arr = expand(B);
        int[] w = arr[0];
        int[] w1 = arr[1];

        for (int j = 0; j < 64; j++) {
            ss1 = (SM3Utils.bitCycleLeft(a, 12) + e + SM3Utils.bitCycleLeft(Tj[j], j));
            ss1 = SM3Utils.bitCycleLeft(ss1, 7);
            ss2 = ss1 ^ SM3Utils.bitCycleLeft(a, 12);
            tt1 = FFj(a, b, c, j) + d + ss2 + w1[j];
            tt2 = GGj(e, f, g, j) + h + ss1 + w[j];
            d = c;
            c = SM3Utils.bitCycleLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = SM3Utils.bitCycleLeft(f, 19);
            f = e;
            e = P0(tt2);
        }
        int[] out = new int[8];
        out[0] = a ^ V[0];
        out[1] = b ^ V[1];
        out[2] = c ^ V[2];
        out[3] = d ^ V[3];
        out[4] = e ^ V[4];
        out[5] = f ^ V[5];
        out[6] = g ^ V[6];
        out[7] = h ^ V[7];

        return out;
    }

    public static byte[] CF(byte[] V, byte[] B) {

        int[] v, b;
        v = SM3Utils.byteArrayConvertIntArray(V);
        b = SM3Utils.byteArrayConvertIntArray(B);
        return SM3Utils.intArrayConvertByteArray(CF(v, b));
    }

    //SM3算法执行
    public static byte[] hash(byte[] source) throws IOException {

        byte[] padding = padding(source);
        int n = padding.length / (512 / 8);
        byte[] b;
        byte[] tempIv = iv;
        byte[] result = null;
        for (int i = 0; i < n; i++) {
            b = Arrays.copyOfRange(padding, i * 64, (i + 1) * 64);
            result = CF(tempIv, b);
            tempIv = result;
        }
        return result;
    }
}
