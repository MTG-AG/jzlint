package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;

/************************************************
 ITU-T X.520 (02/2001) UpperBounds
 ub-street-address INTEGER ::= 128
 ************************************************/

@Lint(
        name = "e_subject_street_address_max_length",
        description = "The 'StreetAddress' field of the subject MUST be less than 129 characters",
        citation = "ITU-T X.520 (02/2001) UpperBounds",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectStreetAddressMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return SubjectOrganizationNameMaxLength.isSubjectComponentGreaterThan(certificate, BCStyle.STREET.getId(), 128);
    }

    // TODO
    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
//    @Override
//    public boolean checkApplies(X509Certificate certificate) {
//        return !Util.getSubjectDNNameComponent(certificate, BCStyle.STREET.getId()).isEmpty();
//    }

}
