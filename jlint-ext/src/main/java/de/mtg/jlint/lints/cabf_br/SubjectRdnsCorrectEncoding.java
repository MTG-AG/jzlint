package de.mtg.jlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * CAs that include attributes in the Certificate subject field that are listed in the table below
 * SHALL encode those attributes in the relative order as they appear in the table and follow the
 * specified encoding requirements for the attribute.
 *
 * <table>
 *   <thead>
 *     <tr><th>Attribute</th><th>Encoding Requirements</th><th>Max Length</th></tr>
 *   <thead>
 *   <tbody>
 *      <tr><td>domainComponent</td><td>MUST use IA5String</td><td>63</td></tr>
 *      <tr><td>countryName</td><td>MUST use PrintableString</td><td>2</td></tr>
 *      <tr><td>stateOrProvinceName</td><td>MUST use UTF8String or PrintableString</td><td>128</td></tr>
 *      <tr><td>localityName</td><td>MUST use UTF8String or PrintableString</td><td>128</td></tr>
 *      <tr><td>postalCode</td><td>MUST use UTF8String or PrintableString</td><td>40</td></tr>
 *      <tr><td>streetAddress</td><td>MUST use UTF8String or PrintableString</td><td>128</td></tr>
 *      <tr><td>organizationName</td><td>MUST use UTF8String or PrintableString</td><td>64</td></tr>
 *      <tr><td>surname</td><td>MUST use UTF8String or PrintableString</td><td>64</td></tr>
 *      <tr><td>givenName</td><td>MUST use UTF8String or PrintableString</td><td>64</td></tr>
 *      <tr><td>organizationalUnitName</td><td>MUST use UTF8String or PrintableString</td><td>64</td></tr>
 *      <tr><td>commonName</td><td>MUST use UTF8String or PrintableString</td><td>64</td></tr>
 *   </tbody>
 * </table>
 */
@Lint(
        name = "e_subject_rdns_correct_encoding",
        description = "CAs that include attributes in the Certificate subject field SHALL follow the specified encoding requirements for the attribute.",
        citation = "BRs: 7.1.4.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class SubjectRdnsCorrectEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Sequence name = ASN1Sequence.getInstance(certificate.getSubjectX500Principal().getEncoded());
        Iterator<ASN1Encodable> iterator = name.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set.getInstance(iterator.next()));
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                AttributeTypeAndValue attributeTypeAndValue = AttributeTypeAndValue.getInstance(rdnIterator.next());
                String oid = attributeTypeAndValue.getType().getId();

                if ("0.9.2342.19200300.100.1.25".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERIA5String)) {
                        return LintResult.of(Status.ERROR, "AVA of type 0.9.2342.19200300.100.1.25 has the wrong encoding.");
                    }
                }
                if ("2.5.4.6".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.6 has the wrong encoding.");
                    }
                }
                if ("2.5.4.8".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.8 has the wrong encoding.");
                    }
                }
                if ("2.5.4.7".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.7 has the wrong encoding.");
                    }
                }
                if ("2.5.4.17".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.17 has the wrong encoding.");
                    }
                }
                if ("2.5.4.9".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.9 has the wrong encoding.");
                    }
                }
                if ("2.5.4.10".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.10 has the wrong encoding.");
                    }
                }
                if ("2.5.4.4".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.4 has the wrong encoding.");
                    }
                }
                if ("2.5.4.42".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.42 has the wrong encoding.");
                    }
                }
                if ("2.5.4.11".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.11 has the wrong encoding.");
                    }
                }
                if ("2.5.4.3".equals(oid)) {
                    ASN1Encodable value = attributeTypeAndValue.getValue();
                    if (!(value instanceof DERUTF8String || value instanceof DERPrintableString)) {
                        return LintResult.of(Status.ERROR, "AVA of type 2.5.4.3 has the wrong encoding.");
                    }
                }
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
