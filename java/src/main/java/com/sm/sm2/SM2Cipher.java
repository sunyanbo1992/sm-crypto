package com.sm.sm2;

import com.sm.SMUtils;
import com.sm.sm3.SM3;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
   SM2 encryptor. It is getting c1, c2, c3 values including KDF function and usage of SM3 algorithm.
 * 
 *
 * @author William Sun
 */
public class SM2Cipher {

    //store（x2,y2）
    private ECPoint p2;
    //random number k
    private BigInteger k;
   
    private byte[] t;

    public SM2Cipher() {
    }

    /**
     * get C1 value
     *
     * @param sm2 SM2
     * @return C1
     */
    public byte[] getC1(SM2 sm2) {

        AsymmetricCipherKeyPair key = sm2.eccKeyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        this.k = ecpriv.getD();
        ECPoint c1 = ecpub.getQ();

        return c1.getEncoded();
    }

    /**
     * get C2 vaue
     *
     * @param plainText （in byte[]）
     * @param publicKey
     * @return C2
     * @throws IOException
     */
    public byte[] getC2(byte[] plainText, ECPoint publicKey) throws IOException {

        this.p2 = publicKey.multiply(k);
        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[64];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(y2, 0, temp, x2.length, y2.length);
        this.t = KDF(temp, plainText.length);

        int count = 0;
        for (int i = 0; i < this.t.length; ++i) {
            if (this.t[i] == 0) {
                count++;
            }
        }
        if (count == this.t.length) {
            return new byte[0];
        }

        int index = 0;
        for (int i = 0; i < plainText.length; i++) {
            plainText[i] ^= t[index++];
        }
        return plainText;
    }

    /**
     * get C3 value
     *
     * @param plainText（byte[]）
     * @return C3
     * @throws IOException
     */
    public byte[] getC3(byte[] plainText) throws IOException {

        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[32 + 32 + plainText.length];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(plainText, 0, temp, x2.length, plainText.length);
        System.arraycopy(y2, 0, temp, x2.length + plainText.length, y2.length);

        return SM3.hash(temp);

    }

    /**
     * C2
     *
     * @param privateKey
     * @param c1
     * @param c2
     * @return plaintext
     * @throws IOException
     */
    public byte[] decryptC2(BigInteger privateKey, ECPoint c1, byte[] c2) throws IOException {
        this.p2 = c1.multiply(privateKey);
        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[64];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(y2, 0, temp, x2.length, y2.length);
        this.t = KDF(temp, c2.length);
        int index = 0;
        for (int i = 0; i < c2.length; i++) {
            c2[i] ^= t[index++];
        }

        return c2;
    }

    /**
     * validate C3 with original C3
     *
     * @param plainText
     * @param originalC3
     * @return validation results
     * @throws IOException
     */
    public boolean verifyC3(byte[] plainText, byte[] originalC3) throws IOException {

        byte[] x2 = SMUtils.byteConvert32Bytes(p2.normalize().getXCoord().toBigInteger());
        byte[] y2 = SMUtils.byteConvert32Bytes(p2.normalize().getYCoord().toBigInteger());
        byte[] temp = new byte[32 + plainText.length + 32];
        System.arraycopy(x2, 0, temp, 0, x2.length);
        System.arraycopy(plainText, 0, temp, x2.length, plainText.length);
        System.arraycopy(y2, 0, temp, x2.length + plainText.length, y2.length);
        byte[] generateC3 = SM3.hash(temp);

        return SMUtils.byteToHex(originalC3).equals(SMUtils.byteToHex(generateC3));
    }

   
    private byte[] KDF(byte[] Z, int kLen) throws IOException {

        int ct = 1;
        byte[] ctByte;
        byte[] buffer = new byte[kLen];
        byte[] ctZ = new byte[Z.length + 4];
        byte[] digest;
        int digestLength = 32;
        int n = (kLen + 31) / 32;
        System.arraycopy(Z, 0, ctZ, 0, Z.length);

        for (int i = 0; i < n; i++) {
            ctByte = SMUtils.intToByteArray(ct);
            System.arraycopy(ctByte, 0, ctZ, Z.length, ctByte.length);
            digest = SM3.hash(ctZ);

            if (i == n - 1) {

                if (kLen % 32 != 0) {
                    digestLength = kLen % 32;
                }
            }
            System.arraycopy(digest, 0, buffer, 32 * i, digestLength);
            ct++;
        }
        byte[] result = new byte[kLen];
        System.arraycopy(buffer, 0, result, 0, kLen);

        return result;
    }

}
