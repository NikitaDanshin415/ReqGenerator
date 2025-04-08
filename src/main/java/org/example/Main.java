package org.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;


//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    public static void main(String[] args) throws Exception {
        // Параметры CSR (можно вынести в аргументы или конфиг)
        String country = "RU";
        String state = "Moscow";
        String locality = "Moscow";
        String organization = "Example Inc";
        String organizationalUnit = "IT";
        String commonName = "example.com";
        String email = "admin@example.com";

        // Генерация ключевой пары RSA
        KeyPair keyPair = generateKeyPair(2048);
        PrivateKey privateKey = keyPair.getPrivate();

        // Создание CSR
        PKCS10CertificationRequest csr = generateCSR(
                keyPair,
                country,
                state,
                locality,
                organization,
                organizationalUnit,
                commonName,
                email
        );

        // Сохранение CSR в файл
        saveToFile("request.req", csr);
        System.out.println("CSR успешно создан: request.req");

        // (Опционально) Сохранение приватного ключа
        savePrivateKey("private.key", privateKey, null); // Без пароля
        System.out.println("Приватный ключ сохранён: private.key");
    }

    // Генерация RSA-ключа
    private static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    // Создание CSR
    private static PKCS10CertificationRequest generateCSR(
            KeyPair keyPair,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            String commonName,
            String email
    ) throws Exception {
        // Формирование Distinguished Name (DN)
        X500Name subject = new X500Name(
                "CN=" + commonName +
                        ", OU=" + organizationalUnit +
                        ", O=" + organization +
                        ", L=" + locality +
                        ", ST=" + state +
                        ", C=" + country +
                        ", EMAILADDRESS=" + email
        );

        // Подпись CSR
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // Создание CSR
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                subject,
                keyPair.getPublic()
        );

        return csrBuilder.build(signer);
    }

    // Сохранение CSR в PEM-формате
    private static void saveToFile(String filename, PKCS10CertificationRequest csr) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            pemWriter.writeObject(csr);
        }
    }

    // Сохранение приватного ключа (опционально)
    private static void savePrivateKey(String filename, PrivateKey privateKey, String password) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            if (password != null) {
                PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                        .setProvider("BC")
                        .build(password.toCharArray());
                pemWriter.writeObject(privateKey, encryptor);
            } else {
                pemWriter.writeObject(privateKey);
            }
        }
    }
}