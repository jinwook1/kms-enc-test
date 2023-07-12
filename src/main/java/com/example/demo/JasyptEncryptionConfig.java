package com.example.demo;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.StringEncryptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

@Slf4j
@Configuration
@EnableEncryptableProperties
public class JasyptEncryptionConfig {


  @Bean
  public StringEncryptor jasyptConfigEncryptor(SzsKmsProperties kmsProperties) {
    return new KmsEncryptor(kmsProperties);
  }

  public static class KmsEncryptor implements StringEncryptor {

    private final SzsKmsProperties kmsProperties;
    private final AwsBasicCredentials credentials;

    public KmsEncryptor(SzsKmsProperties kmsProperties) {
      this.kmsProperties = kmsProperties;
      this.credentials = AwsBasicCredentials.create(kmsProperties.getId(), kmsProperties.getPw());
    }

    KmsClient kmsClient(AwsCredentialsProvider credentialsProvider) {
      return KmsClient.builder()
          .region(Region.AP_NORTHEAST_2)
          .credentialsProvider(credentialsProvider)
          .build();
    }

    @Override
    public String encrypt(String message) {
      return Base64.getEncoder()
          .encodeToString(encryptData(kmsClient(StaticCredentialsProvider.create(credentials)), kmsProperties.getKeyId(), message).asByteArray());
    }

    @Override
    public String decrypt(String encryptedMessage) {
      return decryptData(kmsClient(StaticCredentialsProvider.create(credentials)), SdkBytes.fromByteArray(Base64.getDecoder().decode(encryptedMessage)),
          kmsProperties.getKeyId()).asUtf8String();
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

  }

}
