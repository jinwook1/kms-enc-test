package com.example.demo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@NoArgsConstructor
@Getter
@Setter
@ConfigurationProperties(prefix = "szs.kms")
public class SzsKmsProperties {

  private String keyId;
  private String algorithm;
  private String secret;

  private String region;
  private String id;
  private String pw;
}
