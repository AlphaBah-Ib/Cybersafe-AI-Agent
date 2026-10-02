# -*- coding: utf-8 -*-
"""
v1.8.1 — constat de la regle de blocage apres un ban (rule_present).

    python -m unittest discover -s tests -p "test_remediation_rule.py" -v
"""
import unittest
from unittest import mock

from cybersafe_agent import remediation as r

IP = "1.2.3.4"


def _proc(rc):
    return mock.Mock(returncode=rc, stdout="", stderr="")


class RuleCheckTests(unittest.TestCase):

    def test_rule_present_uses_read_only_check(self):
        with mock.patch.object(r.subprocess, "run", return_value=_proc(0)) as run:
            self.assertIs(r._rule_present(IP, "iptables"), True)
        self.assertEqual(run.call_args[0][0], ["iptables", "-C", "INPUT", "-s", IP, "-j", "DROP"])

    def test_rule_absent(self):
        with mock.patch.object(r.subprocess, "run", return_value=_proc(1)):
            self.assertIs(r._rule_present(IP, "iptables"), False)

    def test_undetermined_cases_return_none(self):
        with mock.patch.object(r.subprocess, "run", return_value=_proc(4)):
            self.assertIsNone(r._rule_present(IP, "iptables"))
        with mock.patch.object(r.subprocess, "run", side_effect=OSError("boom")):
            self.assertIsNone(r._rule_present(IP, "iptables"))
        self.assertIsNone(r._rule_present(IP, None))

    def test_report_sends_rule_only_when_known(self):
        with mock.patch.object(r.requests, "post") as post:
            r._report("https://x/api", "t", 5, True, "ok")
            self.assertNotIn("rule_present", post.call_args.kwargs["json"])
            r._report("https://x/api", "t", 5, True, "ok", rule_present=False)
            self.assertIs(post.call_args.kwargs["json"]["rule_present"], False)

    def test_ban_reports_the_rule_check(self):
        with mock.patch.object(r, "_active_ssh_source_ips", return_value=set()), \
             mock.patch.object(r, "_detect_firewall", return_value="iptables"), \
             mock.patch.object(r, "_apply_ban", return_value=(True, "iptables: ")), \
             mock.patch.object(r, "_rule_present", return_value=True), \
             mock.patch.object(r, "_report") as rep:
            r._process_order({"id": 9, "action": "ban_ip", "target_ip": IP}, "u", "t")
        rep.assert_called_once_with("u", "t", 9, True, "iptables: ", rule_present=True)

    def test_unban_and_failures_send_no_rule_check(self):
        with mock.patch.object(r, "_detect_firewall", return_value="iptables"), \
             mock.patch.object(r, "_apply_unban", return_value=(True, "iptables rc=0")), \
             mock.patch.object(r, "_rule_present") as check, \
             mock.patch.object(r, "_report") as rep:
            r._process_order({"id": 10, "action": "unban_ip", "target_ip": IP}, "u", "t")
        check.assert_not_called()
        rep.assert_called_once_with("u", "t", 10, True, "iptables rc=0", rule_present=None)


if __name__ == "__main__":
    unittest.main()
