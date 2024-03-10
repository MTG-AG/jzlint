package de.mtg.jlint.lints.cabf_br;

import de.mtg.jzlint.*;
import de.mtg.jzlint.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * When encoding a Name, the CA SHALL ensure that:
 * - Each Name MUST contain an RDNSequence.
 * - Each RelativeDistinguishedName MUST contain exactly one AttributeTypeAndValue.
 */
@Lint(
        name = "e_subject_rdn_one_ava",
        description = "Each RelativeDistinguishedName in subjectDN MUST contain exactly one AttributeTypeAndValue",
        citation = "BRs: 7.1.4.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class SubjectRdnOneAva implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Sequence name = ASN1Sequence.getInstance(certificate.getSubjectX500Principal().getEncoded());
        Iterator<ASN1Encodable> iterator = name.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set.getInstance(iterator.next()));
            if (rdn.size() != 1) {
                return LintResult.of(Status.ERROR, "Multi-valued RDNs are not allowed.");
            }
        }
        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
