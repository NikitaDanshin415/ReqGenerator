package org.example;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class RsaWIthSAN {


    public static void main(String[] args) throws Exception {
        // Основные параметры CSR
        String country = "RU";
        String state = "Moscow";
        String locality = "Moscow";
        String organization = "Example Inc";
        String organizationalUnit = "IT";
        String commonName = "example.com";
        String email = "admin@example.com";

        // Subject Alternative Names (только DNS)
        List<String> sanDnsNames = Arrays.asList(
                "example.com",
                "www.example.com",
                "mail.example.com"
        );

        // Генерация ключевой пары RSA
        KeyPair keyPair = generateKeyPair(2048);
        PrivateKey privateKey = keyPair.getPrivate();

        // Создание CSR с SAN (DNS)
        PKCS10CertificationRequest csr = generateCSRWithDNS(
                keyPair,
                country,
                state,
                locality,
                organization,
                organizationalUnit,
                commonName,
                email,
                sanDnsNames
        );

        // Сохранение CSR в файл
        saveToFile("request_dns_only.req", csr);
        System.out.println("CSR с DNS-SAN создан: request_dns_only.req");

        // Сохранение приватного ключа (без пароля)
        savePrivateKey("private.key", privateKey, null);
        System.out.println("Приватный ключ сохранён: private.key");
    }

    // Генерация RSA-ключа
    private static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    // Создание CSR с DNS-SAN
    private static PKCS10CertificationRequest generateCSRWithDNS(
            KeyPair keyPair,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            String commonName,
            String email,
            List<String> sanDnsNames
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

        // Создание SAN-расширения (только DNS)
        GeneralNames sanNames = new GeneralNames(
                buildDNSNames(sanDnsNames)
        );

        // Добавление SAN в расширения CSR
        Extensions extensions = new Extensions(
                new Extension(Extension.subjectAlternativeName, false, sanNames.getEncoded())
        );

        // Подпись CSR
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // Создание CSR с расширениями
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                subject,
                keyPair.getPublic()
        ).addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extensions
        );

        return csrBuilder.build(signer);
    }

    // Формирование GeneralName только для DNS
    private static GeneralName[] buildDNSNames(List<String> dnsNames) {
        List<GeneralName> names = new ArrayList<>();

        for (String dnsName : dnsNames) {
            names.add(new GeneralName(GeneralName.dNSName, dnsName));
        }

        return names.toArray(new GeneralName[0]);
    }

    // Сохранение CSR в PEM-формате
    private static void saveToFile(String filename, PKCS10CertificationRequest csr) throws IOException {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            pemWriter.writeObject(csr);
        }
    }

    // Сохранение приватного ключа (опционально с паролем)
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