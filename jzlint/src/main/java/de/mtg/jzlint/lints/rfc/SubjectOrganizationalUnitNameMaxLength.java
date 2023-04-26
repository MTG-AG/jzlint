package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-organizational-unit-name INTEGER ::= 64
 ************************************************/
@Lint(
        name = "e_subject_organizational_unit_name_max_length",
        description = "The 'Organizational Unit Name' field of the subject MUST be less than 65 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectOrganizationalUnitNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return SubjectOrganizationNameMaxLength.isSubjectComponentGreaterThan(certificate, X509ObjectIdentifiers.organizationalUnitName.getId(), 64);
    }

    // TODO
    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

//    @Override
//    public boolean checkApplies(X509Certificate certificate) {
//        return !Util.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organizationalUnitName.getId()).isEmpty();
//    }

}
