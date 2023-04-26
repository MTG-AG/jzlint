package de.mtg.jzlint.lints.cabf_br;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*******************************************************************************************************
 "BRs: 6.1.6"
 RSA: The CA SHALL confirm that the value of the public
 exponent is an odd number equal to 3 or more.
 Additionally, the public exponent SHOULD be
 in the range between 2^16+1 and 2^256-1.
 The modulus SHOULD also have the following
 characteristics: an odd number, not the power
 of a prime, and have no factors smaller than
 752. [Citation: Section 5.3.3, NIST SP 800‐89].
 *******************************************************************************************************/

@Lint(
        name = "w_rsa_mod_not_odd",
        description = "RSA: Modulus SHOULD also have the following characteristics: an odd number",
        citation = "BRs: 6.1.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV113Date)
public class RsaModNotOdd implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        if (rsaPublicKey.getModulus().mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }


}
