package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;


/************************************************
 RFC 5280: A.1
 -- Naming attributes of type X520name
 id-at-givenName           AttributeType ::= { id-at 42 }
 -- Naming attributes of type X520Name:
 --   X520name ::= DirectoryString (SIZE (1..ub-name))
 --
 -- Expanded to avoid parameterized type:
 X520name ::= CHOICE {
 teletexString     TeletexString   (SIZE (1..ub-name)),
 printableString   PrintableString (SIZE (1..ub-name)),
 universalString   UniversalString (SIZE (1..ub-name)),
 utf8String        UTF8String      (SIZE (1..ub-name)),
 bmpString         BMPString       (SIZE (1..ub-name)) }
 --  specifications of Upper Bounds MUST be regarded as mandatory
 --  from Annex B of ITU-T X.411 Reference Definition of MTS Parameter
 --  Upper Bounds
 -- Upper Bounds
 ub-name INTEGER ::= 32768
 ************************************************/

@Lint(
        name = "e_subject_given_name_max_length",
        description = "The 'GivenName' field of the subject MUST be less than 32769 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectGivenNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return SubjectOrganizationNameMaxLength.isSubjectComponentGreaterThan(certificate, BCStyle.GIVENNAME.getId(), 32768);
    }

    // TODO
    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
//    @Override
//    public boolean checkApplies(X509Certificate certificate) {
//        return !Util.getSubjectDNNameComponent(certificate, BCStyle.EmailAddress.getId()).isEmpty();
//    }
}
