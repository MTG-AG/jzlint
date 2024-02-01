package de.mtg.jzlint.lints.cabf_br;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LintTestExtension.class)
class SubjectCommonNameIncludedWTest {

    @LintTest(
            name = "w_subject_common_name_included",
            filename = "commonNameExistsSC62.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_subject_common_name_included",
            filename = "commonNameGoodSC62.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
