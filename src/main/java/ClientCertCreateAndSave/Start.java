package ClientCertCreateAndSave;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Start {
	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";
	public final static String LINE_SEPARATOR = System.getProperty("line.separator");

	public static void main(String[] args) {
		try (FileOutputStream fos = new FileOutputStream("//Users//venkat//Desktop//KS");) {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(4096);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			X509Certificate cert = generateCertificate("cn=AutomationAnywhere", keyPair, 365, "SHA256withRSA");
			writeCertToFile(cert);
			System.out.println(cert);
			System.out.println(formatCrtFileContents(cert));

			Certificate[] chain = { cert };

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
			keyStore.setKeyEntry("main", keyPair.getPrivate(), "654321".toCharArray(), chain);
			keyStore.store(fos, "123456".toCharArray());
			System.out.println("");
		} catch (IOException | GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

	public static String formatCrtFileContents(final Certificate certificate) throws CertificateEncodingException {
		final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

		final byte[] rawCrtText = certificate.getEncoded();
		final String encodedCertText = new String(encoder.encode(rawCrtText));
		final String prettified_cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
		return prettified_cert;
	}

	public static void writeCertToFile(X509Certificate cert) {
		
		
		String fileName = "//Users//venkat//Desktop//clientCert"+LocalDateTime.now().toString()+".crt";
		StringBuilder certContent = new StringBuilder();
		certContent.append(cert);
		try {
			certContent.append(formatCrtFileContents(cert));
			Files.write(Paths.get(fileName), certContent.toString().getBytes());
		} catch (CertificateEncodingException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName)
			throws GeneralSecurityException, IOException {
		PrivateKey privateKey = keyPair.getPrivate();

		X509CertInfo info = new X509CertInfo();

		Date from = new Date();
		Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

		CertificateValidity interval = new CertificateValidity(from, to);
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		X500Name owner = new X500Name(dn);
		AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, owner);
		info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl certificate = new X509CertImpl(info);
		certificate.sign(privateKey, sigAlgName);

		// Update the algorith, and resign.
		sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
		certificate = new X509CertImpl(info);
		certificate.sign(privateKey, sigAlgName);
		return certificate;
	}
}
