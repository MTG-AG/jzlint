package de.mtg.jzlint.ca;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Certificates for lints: w_etsi_natural_person_key_usage_preferred_values
 */
public class CreateCertificate021 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";
    private static final X500Name CA_ISSUER_DN = new X500Name("CN=Lint CA, O=Lint, C=DE");
    private static PrivateKey caPrivateKey;

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        caPrivateKey = keyPair.getPrivate();

        var zlintTestVectors = new StringBuilder();

        //QCPnPolicyOID              = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 0}
        //QCPlPolicyOID              = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 1}
        //QCPnqscdPolicyOID          = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 2}
        //QCPlqscdPolicyOID          = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 3}
        //QEVCPwPolicyOID            = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 4}
        //QNCPwPolicyOID             = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 5}
        //QNCPwgenPolicyOID          = asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 6}

        {

            String name = "qcNaturalWithKU";
            String expectedResult = "Pass";
            String details = "certificate is issued to a natural person and has keu usage extension with recommended value, i.e keyEncipherment only";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.GIVENNAME, new DERUTF8String("givenName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.0", keyUsage);//QCPnPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/",  namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        {

            String name = "qcLegalWithKU";
            String expectedResult = "NA";
            String details = "certificate is issued to a legal person and has keu usage extension";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.GIVENNAME, new DERUTF8String("givenName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.1", keyUsage);//QCPlPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/", namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        {

            String name = "qcNaturalWithoutKU";
            String expectedResult = "NA";
            String details = "certificate is issued to a natural person and does not have the keu usage extension";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.GIVENNAME, new DERUTF8String("givenName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.0", null);//QCPnPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/", namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        {

            String name = "qcNaturalOrLegalWithKU";
            String expectedResult = "NA";
            String details = "certificate is issued to a legal person because subjectDN parts for natural persons are not present";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.CN, new DERUTF8String("commonName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.4", keyUsage);//QEVCPwPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/", namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        {

            String name = "qcNaturalWithAllowedKU";
            String expectedResult = "Pass";
            String details = "certificate is issued to a natural person and has keu usage extension with digital signature only";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.GIVENNAME, new DERUTF8String("givenName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.5", keyUsage);//QNCPwPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/", namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        {

            String name = "qcNaturallWithNotRecommendedKU";
            String expectedResult = "Warn";
            String details = "certificate is issued to a natural person and has keu usage extension with digitalSignature and nonRepudiation";

            String expectedDetails = "%s - %s".formatted(expectedResult, details);

            RDN rdn = new RDN(BCStyle.GIVENNAME, new DERUTF8String("givenName"));

            List<RDN> rdns = new ArrayList<>();
            rdns.add(rdn);
            X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
            X509Certificate testCertificate = createTestCertificate(subjectDN, "0.4.0.194112.1.6", keyUsage);//QNCPwgenPolicyOID

            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            Utils.handleIssuedCertificateMore(args, nameDER, testCertificate, "etsi/", namePEM, zlintTestVectors, expectedResult, expectedDetails);
        }

        System.out.println(zlintTestVectors);

    }

    private static X509Certificate createTestCertificate(X500Name subjectDN, String policyOID, KeyUsage keyUsage) throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        ZonedDateTime notBefore = ZonedDateTime.of(2025, 2, 18, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(3).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        CertificatePolicies qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {
                new PolicyInformation(new ASN1ObjectIdentifier(policyOID))
        });
        
        QCStatement qcStatement = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.1"));
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(qcStatement);
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(CA_ISSUER_DN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);


        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));
        certificateBuilder.addExtension(new Extension(Extension.certificatePolicies, true, new DEROctetString(qcCertificatePolicies)));

        if (keyUsage != null) {
            Extension ku = new Extension(Extension.keyUsage, true, keyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            certificateBuilder.addExtension(ku);
        }

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }


    private static X509Certificate createErrorTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore, X500Name subjectDN,
            String policyOID, boolean withMIMEPolicy)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(3).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        CertificatePolicies qcCertificatePolicies;
        if (withMIMEPolicy) {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {
                    new PolicyInformation(new ASN1ObjectIdentifier(policyOID)),
                    new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.5.1.2")), // mailboxValidatedMultipurposeOID
            });
        } else {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {new PolicyInformation(new ASN1ObjectIdentifier(policyOID))});
        }

        QCStatement qcStatement = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.1"));
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(qcStatement);
        qcStatements.add(createEsi4QcStatement6(ETSIQCObjectIdentifiers.id_etsi_qct_web));
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));
        certificateBuilder.addExtension(new Extension(Extension.certificatePolicies, true, new DEROctetString(qcCertificatePolicies)));
        certificateBuilder.addExtension(
                new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static QCStatement createEsi4QcStatement6(ASN1ObjectIdentifier oid) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(oid);

        return new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(vector));
    }

}