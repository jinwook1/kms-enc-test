package com.example.demo;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.KmsException;

@RestController
public class TestController {

  private final SzsKmsProperties kmsProperties;
  private final AwsBasicCredentials credentials;
  @Value("${test}")
  String test;

  public TestController(SzsKmsProperties kmsProperties) {
    this.kmsProperties = kmsProperties;
    this.credentials = AwsBasicCredentials.create(kmsProperties.getId(), kmsProperties.getPw());
  }

  private SdkBytes encryptData(KmsClient kmsClient, String keyId, String rawData) {

    try {
      SdkBytes myBytes = SdkBytes.fromString(rawData, StandardCharsets.UTF_8);

      EncryptRequest encryptRequest = EncryptRequest.builder()
          .keyId(keyId)
          .plaintext(myBytes)
          .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
          .build();

      EncryptResponse response = kmsClient.encrypt(encryptRequest);
      String algorithm = response.encryptionAlgorithm().toString();
      System.out.println("The encryption algorithm is " + algorithm);

      // Get the encrypted data.
      SdkBytes encryptedData = response.ciphertextBlob();
      return encryptedData;

    } catch (KmsException e) {
      e.printStackTrace();
      return null;
    }
  }

  private SdkBytes decryptData(KmsClient kmsClient, SdkBytes encryptedData, String keyId) {

    try {
      DecryptRequest decryptRequest = DecryptRequest.builder()
          .ciphertextBlob(encryptedData)
          .keyId(keyId)
          .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
          .build();

      DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
      return decryptResponse.plaintext();
    } catch (KmsException e) {
      e.printStackTrace();
      return null;
    }
  }

  @GetMapping
  public String hello()
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

    KmsClient kmsClient = kmsClient(StaticCredentialsProvider.create(credentials));
    String rawData = "raw string";
    SdkBytes encrypted = encryptData(kmsClient, kmsProperties.getKeyId(), rawData);
    SdkBytes decrypted = decryptData(kmsClient, encrypted, kmsProperties.getKeyId());
    String encString = Base64.getEncoder().encodeToString(encrypted.asByteArray());
    String decString = decrypted.asUtf8String();
    String encUtilString = RSAUtil.encryptRSA(rawData, RSAUtil.getPublicKeyFromBase64Encrypted(kmsProperties.getSecret()));
    SdkBytes decUtilString = decryptData(kmsClient, SdkBytes.fromByteArray(Base64.getDecoder().decode(encUtilString)), kmsProperties.getKeyId());
    return String.format("%s:\n%s\n%s\n%s\n%s", test, encString, decString, encUtilString, decUtilString.asUtf8String());
  }

  KmsClient kmsClient(AwsCredentialsProvider credentialsProvider) {
    return KmsClient.builder()
        .region(Region.AP_NORTHEAST_2)
        .credentialsProvider(credentialsProvider)
        .build();
  }
}
