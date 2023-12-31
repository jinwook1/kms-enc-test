package com.example.demo;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RSAUtil {

  /**
   * 1024비트 RSA 키쌍을 생성
   */
  public static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSAES_OAEP_SHA_256");
    gen.initialize(1024, new SecureRandom());
    return gen.genKeyPair();
  }

  /**
   * Public Key로 RSA 암호화를 수행
   */
  public static String encryptRSA(String plainText, PublicKey publicKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

    byte[] bytePlain = cipher.doFinal(plainText.getBytes());
    return Base64.getEncoder().encodeToString(bytePlain);
  }

  /**
   * Private Key로 RSA 복호화를 수행
   */
  public static String decryptRSA(String encrypted, PrivateKey privateKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
    byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

    cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
    byte[] bytePlain = cipher.doFinal(byteEncrypted);
    return new String(bytePlain, "utf-8");
  }

  public static PublicKey getPublicKeyFromBase64Encrypted(String base64PublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    String replaced = base64PublicKey
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("[\s\n]", "");
    byte[] decodedBase64PubKey = Base64.getDecoder().decode(replaced);

    return KeyFactory.getInstance("RSA")
        .generatePublic(new X509EncodedKeySpec(decodedBase64PubKey));
  }

  public static PrivateKey getPrivateKeyFromBase64Encrypted(String base64PrivateKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] decodedBase64PrivateKey = Base64.getDecoder().decode(base64PrivateKey);

    return KeyFactory.getInstance("RSAES_OAEP_SHA_256")
        .generatePrivate(new PKCS8EncodedKeySpec(decodedBase64PrivateKey));
  }

}
