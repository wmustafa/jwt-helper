package com.symphony.util.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Stream;


/**
 * Class used to generate JWT tokens signed by a specified private RSA key.
 * Libraries needed as dependencies:
 *  - BouncyCastle (org.bouncycastle.bcpkix-jdk15on) version 1.59.
 *  - JJWT (io.jsonwebtoken.jjwt) version 0.9.1.
 *
 *
 */
public class JwtHelper {

    // PKCS#8 format
    private static final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

    // PKCS#1 format
    private static final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";


    /**
     * Get file as string without spaces
     * @param filePath: filepath for the desired file.
     * @return
     */
    public static String getFileAsString(String filePath) throws IOException {
        StringBuilder message = new StringBuilder();
        String newline = System.getProperty("line.separator");

        if (!Files.exists(Paths.get(filePath))) {
            throw new FileNotFoundException("File " + filePath + " was not found.");
        }

        try (Stream<String> stream = Files.lines(Paths.get(filePath))) {

            stream.forEach(line -> message
                    .append(line)
                    .append(newline));

            // Remove last new line.
            message.deleteCharAt(message.length() -1);
        } catch (IOException e) {
            System.out.println(String.format("Could not load content from file: %s due to %s",filePath, e));
            System.exit(1);
        }

        return message.toString();
    }

    /**
     * Creates a JWT with the provided user name and expiration date, signed with the provided private key.
     * @param user the username to authenticate; will be verified by the pod
     * @param expiration of the authentication request in milliseconds; cannot be longer than the value defined on the pod
     * @param privateKey the private RSA key to be used to sign the authentication request; will be checked on the pod against
     * the public key stored for the user
     */
    private static String createSignedJwt(String user, long expiration, Key privateKey) {

        return Jwts.builder()
                .setSubject(user)
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.RS512, privateKey)
                .compact();
    }

    /**
     * Create a RSA Private Key from a PEM String. It supports PKCS#1 and PKCS#8 string formats
     */
    private static PrivateKey parseRSAPrivateKey(String privateKeyFilePath) throws GeneralSecurityException, IOException {
        String pemPrivateKey = getFileAsString(privateKeyFilePath);
        try {

            if (pemPrivateKey.contains(PEM_PRIVATE_START)) {              // PKCS#8 format

                String privateKeyString = pemPrivateKey
                        .replace(PEM_PRIVATE_START, "")
                        .replace(PEM_PRIVATE_END, "")
                        .replace("\\n", "\n")
                        .replaceAll("\\s", "");
                byte[] keyBytes = Base64.getDecoder().decode(privateKeyString.getBytes(StandardCharsets.UTF_8));
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory fact = KeyFactory.getInstance("RSA");
                return fact.generatePrivate(keySpec);

            } else if (pemPrivateKey.contains(PEM_RSA_PRIVATE_START)) {   // PKCS#1 format

                try (PemReader pemReader = new PemReader(new StringReader(pemPrivateKey))) {
                    PemObject privateKeyObject = pemReader.readPemObject();
                    RSAPrivateKey rsa = RSAPrivateKey.getInstance(privateKeyObject.getContent());
                    RSAPrivateCrtKeyParameters privateKeyParameter = new RSAPrivateCrtKeyParameters(
                            rsa.getModulus(),
                            rsa.getPublicExponent(),
                            rsa.getPrivateExponent(),
                            rsa.getPrime1(),
                            rsa.getPrime2(),
                            rsa.getExponent1(),
                            rsa.getExponent2(),
                            rsa.getCoefficient()
                    );

                    return new JcaPEMKeyConverter().getPrivateKey(PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParameter));
                } catch (IOException e) {
                    throw new GeneralSecurityException("Invalid private key.");
                }

            } else {
                throw new GeneralSecurityException("Invalid private key.");
            }
        } catch (Exception e) {
            throw new GeneralSecurityException(e);
        }
    }

    public static String createJwt(String username, String privateKeyFilePath) throws IOException, GeneralSecurityException {
        final long expiration = 300000L;
        final PrivateKey privateKey = parseRSAPrivateKey(privateKeyFilePath);
        return createSignedJwt(username, expiration, privateKey);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        //final String username ="agw-demo@symphony.com" ;//System.getProperty("user");
        String username = "agw-misbehave-demo@symphony.com"; // Misbehaving bot
        final String privateKeyFile = "/Users/wahaj.mustafa/Documents/SymphonyDevelopment/Public-Private-Key-Gen/JWT-Helper/private_key"; //System.getProperty("key");

        final String jwt = createJwt(username, privateKeyFile);
        System.out.println(jwt);
    }
}
