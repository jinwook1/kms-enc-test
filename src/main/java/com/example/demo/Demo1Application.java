package com.example.demo;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
import com.ulisesbocchio.jasyptspringboot.annotation.EncryptablePropertySource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@EnableEncryptableProperties
@ConfigurationPropertiesScan
public class Demo1Application {

  public static void main(String[] args) {
    SpringApplication.run(Demo1Application.class, args);
  }

}
