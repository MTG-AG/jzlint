package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/***************************************************************
 BRs: 7.1.4.2.2
 Required/Optional: Deprecated (Discouraged, but not prohibited)
 ***************************************************************/

@Lint(
        name = "n_subject_common_name_included",
        description = "Subscriber Certificate: commonName is deprecated.",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubjectCommonNameIncluded implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (commonName.isEmpty()) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.NOTICE);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }


}
