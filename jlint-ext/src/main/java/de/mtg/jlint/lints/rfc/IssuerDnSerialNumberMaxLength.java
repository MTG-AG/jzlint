package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_issuer_dn_serial_number_max_length",
        description = "The 'Serial Number' field of the issuer MUST be less than 65 characters",
        citation = "RFC 5280: Appendix A",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class IssuerDnSerialNumberMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, BCStyle.SERIALNUMBER.getId(), 64);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, BCStyle.SERIALNUMBER.getId()).isEmpty();
    }
}
