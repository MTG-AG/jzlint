package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EkuCriticalTest {

    @LintTest(
            name = "e_eku_critical",
            filename = "ekuCrit.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_eku_critical",
            filename = "ekuNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
