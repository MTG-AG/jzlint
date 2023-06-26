package de.mtg.jlint.lints.rfc;

import de.mtg.jzlint.*;
import de.mtg.jzlint.utils.Utils;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.cert.X509Certificate;
import java.util.List;

/************************************************
 RFC 5280: A.1
 --  specifications of Upper Bounds MUST be regarded as mandatory
 --  from Annex B of ITU-T X.411 Reference Definition of MTS Parameter
 --  Upper Bounds
 ************************************************/
@Lint(
        name = "w_issuer_given_name_recommended_max_length",
        description = "X.411 (1988) describes ub-given-name-length to be 16 characters long. As systems may have targeted this length, for compatibility purposes it may be prudent to limit given names to this length.",
        citation = "ITU-T Rec. X.411 (11/1988), Annex B Reference Definition of MTS Parameter Upper Bounds",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerGivenNameRecommendedMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> issuerNameComponent = Utils.getIssuerDNNameComponent(certificate, BCStyle.GIVENNAME.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : issuerNameComponent) {
            if (attributeTypeAndValue.getValue().toString().length() > 16) {
                return LintResult.of(Status.WARN);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, BCStyle.GIVENNAME.getId()).isEmpty();
    }

}
