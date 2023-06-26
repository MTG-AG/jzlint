package de.mtg.jlint.lints.rfc;

import de.mtg.jzlint.*;
import de.mtg.jzlint.utils.Utils;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.cert.X509Certificate;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-postal-code-length INTEGER ::= 16
 ************************************************/

@Lint(
        name = "e_issuer_postal_code_max_length",
        description = "The 'PostalCode' field of the issuer MUST be less than 17 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerPostalCodeMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, BCStyle.POSTAL_CODE.getId(), 17);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, BCStyle.POSTAL_CODE.getId()).isEmpty();
    }

}
