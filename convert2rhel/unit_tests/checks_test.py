# -*- coding: utf-8 -*-
#
# Copyright(C) 2018 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from collections import namedtuple
import os
import subprocess
import sys

import pytest

from convert2rhel import checks, grub, unit_tests
from convert2rhel.unit_tests import GetLoggerMocked
from convert2rhel.utils import run_subprocess


try:
    import unittest2 as unittest  # Python 2.6 support
except ImportError:
    import unittest


if sys.version_info[:2] <= (2, 7):
    import mock  # pylint: disable=import-error
else:
    from unittest import mock  # pylint: disable=no-name-in-module


HOST_MODULES_STUB_GOOD = (
    "/lib/modules/5.8.0-7642-generic/kernel/lib/a.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/b.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/c.ko.xz\n"
)
HOST_MODULES_STUB_BAD = (
    "/lib/modules/5.8.0-7642-generic/kernel/lib/d.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/e.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/f.ko.xz\n"
)
REPOQUERY_F_STUB_GOOD = (
    "kernel-core-0:4.18.0-240.10.1.el8_3.x86_64\n"
    "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64\n"
    "kernel-debug-core-0:4.18.0-240.10.1.el8_3.x86_64\n"
    "kernel-debug-core-0:4.18.0-240.15.1.el8_3.x86_64\n"
)
REPOQUERY_F_STUB_BAD = (
    "kernel-idontexpectyou-core-sdsdsd.ell8_3.x86_64\n"
    "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64\n"
    "kernel-debug-core-0:4.18.0-240.10.1.el8_3.x86_64\n"
    "kernel-debug-core-0:4.18.0-240.15.1.el8_3.x86_64\n"
)
REPOQUERY_L_STUB_GOOD = (
    "/lib/modules/5.8.0-7642-generic/kernel/lib/a.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/a.ko\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/b.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/c.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/c.ko\n"
)
REPOQUERY_L_STUB_BAD = (
    "/lib/modules/5.8.0-7642-generic/kernel/lib/d.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/d.ko\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/e.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/f.ko.xz\n"
    "/lib/modules/5.8.0-7642-generic/kernel/lib/f.ko\n"
)


def _run_subprocess_side_effect(*stubs):
    def factory(*args, **kwargs):
        for kws, result in stubs:
            if all(kw in args[0] for kw in kws):
                return result
        else:
            return run_subprocess(*args, **kwargs)

    return factory


def test_perform_pre_checks(monkeypatch):
    check_thirdparty_kmods_mock = mock.Mock()
    check_efi_mock = mock.Mock()
    monkeypatch.setattr(
        checks,
        "check_efi",
        value=check_efi_mock,
    )
    monkeypatch.setattr(
        checks,
        "check_tainted_kmods",
        value=check_thirdparty_kmods_mock,
    )

    checks.perform_pre_checks()

    check_thirdparty_kmods_mock.assert_called_once()
    check_efi_mock.assert_called_once()


def test_pre_ponr_checks(monkeypatch):
    ensure_compatibility_of_kmods_mock = mock.Mock()
    monkeypatch.setattr(
        checks,
        "ensure_compatibility_of_kmods",
        value=ensure_compatibility_of_kmods_mock,
    )
    checks.perform_pre_ponr_checks()
    ensure_compatibility_of_kmods_mock.assert_called_once()


@pytest.mark.parametrize(
    (
        "host_kmods",
        "exception",
        "should_be_in_logs",
        "shouldnt_be_in_logs",
    ),
    (
        (
            HOST_MODULES_STUB_GOOD,
            None,
            "Kernel modules are compatible",
            None,
        ),
        (
            HOST_MODULES_STUB_BAD,
            SystemExit,
            None,
            "Kernel modules are compatible",
        ),
    ),
)
def test_ensure_compatibility_of_kmods(
    monkeypatch,
    pretend_centos8,
    caplog,
    host_kmods,
    exception,
    should_be_in_logs,
    shouldnt_be_in_logs,
):
    run_subprocess_mock = mock.Mock(
        side_effect=_run_subprocess_side_effect(
            (("uname",), ("5.8.0-7642-generic\n", 0)),
            (("find",), (host_kmods, 0)),
            (("repoquery", " -f "), (REPOQUERY_F_STUB_GOOD, 0)),
            (("repoquery", " -l "), (REPOQUERY_L_STUB_GOOD, 0)),
        )
    )
    monkeypatch.setattr(
        checks,
        "run_subprocess",
        value=run_subprocess_mock,
    )

    if exception:
        with pytest.raises(exception):
            checks.ensure_compatibility_of_kmods()
    else:
        checks.ensure_compatibility_of_kmods()

    if should_be_in_logs:
        assert should_be_in_logs in caplog.records[-1].message
    if shouldnt_be_in_logs:
        assert shouldnt_be_in_logs not in caplog.records[-1].message


@pytest.mark.parametrize(
    (
        "unsupported_pkg",
        "msg_in_logs",
        "msg_not_in_logs",
        "exception",
    ),
    (
        (
            "/lib/modules/3.10.0-1160.6.1/kernel/drivers/input/ff-memless.ko.xz\n",
            "Kernel modules are compatible",
            "The following kernel modules are not supported in RHEL",
            None,
        ),
        (
            "/lib/modules/3.10.0-1160.6.1/kernel/drivers/input/other.ko.xz\n",
            "The following kernel modules are not supported in RHEL",
            None,
            SystemExit,
        ),
    ),
)
def test_ensure_compatibility_of_kmods_excluded(
    monkeypatch,
    pretend_centos7,
    caplog,
    unsupported_pkg,
    msg_in_logs,
    msg_not_in_logs,
    exception,
):
    get_unsupported_kmods_mocked = mock.Mock(
        wraps=checks.get_unsupported_kmods
    )
    run_subprocess_mock = mock.Mock(
        side_effect=_run_subprocess_side_effect(
            (("uname",), ("5.8.0-7642-generic\n", 0)),
            (("find",), (HOST_MODULES_STUB_GOOD + unsupported_pkg, 0)),
            (("repoquery", " -f "), (REPOQUERY_F_STUB_GOOD, 0)),
            (("repoquery", " -l "), (REPOQUERY_L_STUB_GOOD, 0)),
        )
    )
    monkeypatch.setattr(
        checks,
        "run_subprocess",
        value=run_subprocess_mock,
    )
    monkeypatch.setattr(
        checks,
        "get_unsupported_kmods",
        value=get_unsupported_kmods_mocked,
    )
    if exception:
        with pytest.raises(exception):
            checks.ensure_compatibility_of_kmods()
    else:
        checks.ensure_compatibility_of_kmods()
    get_unsupported_kmods_mocked.assert_called_with(
        # host kmods
        set(
            (
                checks._get_kmod_comparison_key(unsupported_pkg.rstrip()),
                "kernel/lib/c.ko.xz",
                "kernel/lib/a.ko.xz",
                "kernel/lib/b.ko.xz",
            )
        ),
        # rhel supported kmods
        set(
            (
                "kernel/lib/c.ko",
                "kernel/lib/b.ko.xz",
                "kernel/lib/c.ko.xz",
                "kernel/lib/a.ko.xz",
                "kernel/lib/a.ko",
            )
        ),
    )
    if msg_in_logs:
        assert msg_in_logs in caplog.records[0].message
    if msg_not_in_logs:
        assert all(
            msg_not_in_logs not in record.message for record in caplog.records
        )


@pytest.mark.parametrize(
    ("run_subprocess_mock", "exp_res"),
    (
        (
            mock.Mock(return_value=(HOST_MODULES_STUB_GOOD, 0)),
            set(
                (
                    "kernel/lib/a.ko.xz",
                    "kernel/lib/b.ko.xz",
                    "kernel/lib/c.ko.xz",
                )
            ),
        ),
        (
            mock.Mock(return_value=("", 1)),
            None,
        ),
        (
            mock.Mock(
                side_effect=subprocess.CalledProcessError(returncode=1, cmd="")
            ),
            None,
        ),
    ),
)
def test_get_installed_kmods(
    tmpdir, monkeypatch, caplog, run_subprocess_mock, exp_res
):
    monkeypatch.setattr(
        checks,
        "run_subprocess",
        value=run_subprocess_mock,
    )
    if exp_res:
        assert exp_res == checks.get_installed_kmods()
    else:
        with pytest.raises(SystemExit):
            checks.get_installed_kmods()
        assert (
            "Can't get list of kernel modules." in caplog.records[-1].message
        )


@pytest.mark.parametrize(
    ("repoquery_f_stub", "repoquery_l_stub", "exception"),
    (
        (REPOQUERY_F_STUB_GOOD, REPOQUERY_L_STUB_GOOD, None),
        (REPOQUERY_F_STUB_BAD, REPOQUERY_L_STUB_GOOD, SystemExit),
    ),
)
def test_get_rhel_supported_kmods(
    monkeypatch,
    pretend_centos8,
    repoquery_f_stub,
    repoquery_l_stub,
    exception,
):
    run_subprocess_mock = mock.Mock(
        side_effect=_run_subprocess_side_effect(
            (
                ("repoquery", " -f "),
                (repoquery_f_stub, 0),
            ),
            (
                ("repoquery", " -l "),
                (repoquery_l_stub, 0),
            ),
        )
    )
    monkeypatch.setattr(
        checks,
        "run_subprocess",
        value=run_subprocess_mock,
    )
    if exception:
        with pytest.raises(exception):
            checks.get_rhel_supported_kmods()
    else:
        res = checks.get_rhel_supported_kmods()
        assert res == set(
            (
                "kernel/lib/a.ko",
                "kernel/lib/a.ko.xz",
                "kernel/lib/b.ko.xz",
                "kernel/lib/c.ko.xz",
                "kernel/lib/c.ko",
            )
        )


@pytest.mark.parametrize(
    ("pkgs", "exp_res", "exception"),
    (
        (
            (
                "kernel-core-0:4.18.0-240.10.1.el8_3.x86_64",
                "kernel-debug-core-0:4.18.0-240.10.1.el8_3.x86_64",
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
                "kernel-debug-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            (
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
                "kernel-debug-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            None,
        ),
        (
            (
                "kmod-core-0:4.18.0-240.10.1.el8_3.x86_64",
                "kmod-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            ("kmod-core-0:4.18.0-240.15.1.el8_3.x86_64",),
            None,
        ),
        (
            (
                "not-expected-core-0:4.18.0-240.10.1.el8_3.x86_64",
                "kmod-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            ("kmod-core-0:4.18.0-240.15.1.el8_3.x86_64",),
            None,
        ),
        (
            (
                "kernel-core-0:4.18.0-240.beta5.1.el8_3.x86_64",
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            ("kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",),
            None,
        ),
        (
            (
                "kernel-core-0:4.18.0-240.15.beta5.1.el8_3.x86_64",
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            ("kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",),
            None,
        ),
        (
            (
                "kernel-core-0:4.18.0-240.16.beta5.1.el8_3.x86_64",
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            ("kernel-core-0:4.18.0-240.16.beta5.1.el8_3.x86_64",),
            None,
        ),
        (("kernel_bad_package:111111",), (), SystemExit),
        (
            (
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
                "kernel_bad_package:111111",
                "kernel-core-0:4.18.0-240.15.1.el8_3.x86_64",
            ),
            (),
            SystemExit,
        ),
    ),
)
def test_get_most_recent_unique_kernel_pkgs(pkgs, exp_res, exception):
    if not exception:
        most_recent_pkgs = tuple(checks.get_most_recent_unique_kernel_pkgs(pkgs))
        assert exp_res == most_recent_pkgs
    else:
        with pytest.raises(exception):
            tuple(checks.get_most_recent_unique_kernel_pkgs(pkgs))


@pytest.mark.parametrize(
    ("command_return", "expected_exception"),
    (
        (
            ("", 0),
            None,
        ),
        (
            (
                (
                    "system76_io 16384 0 - Live 0x0000000000000000 (OE)\n"
                    "system76_acpi 16384 0 - Live 0x0000000000000000 (OE)"
                ),
                0,
            ),
            SystemExit,
        ),
    ),
)
def test_check_tainted_kmods(monkeypatch, command_return, expected_exception):
    run_subprocess_mock = mock.Mock(return_value=command_return)
    monkeypatch.setattr(
        checks,
        "run_subprocess",
        value=run_subprocess_mock,
    )
    if expected_exception:
        with pytest.raises(expected_exception):
            checks.check_tainted_kmods()
    else:
        checks.check_tainted_kmods()


class EFIBootInfoMocked():

    _ENTRIES = {
        "0001": grub.EFIBootLoader(
                    boot_number="0001",
                    label="Centos Linux",
                    active=True,
                    efi_bin_source="HD(1,GPT,28c77f6b-3cd0-4b22-985f-c99903835d79,0x800,0x12c000)/File(\\EFI\\centos\\shimx64.efi)",
        ),
        "0002": grub.EFIBootLoader(
                    boot_number="0002",
                    label="Foo label",
                    active=True,
                    efi_bin_source="FvVol(7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1)/FvFile(462caa21-7614-4503-836e-8ab6f4662331)",
        ),
    }

    def __init__(self,
                 current_boot="0001",
                 next_boot=None,
                 boot_order=("0001", "0002"),
                 entries=_ENTRIES,
                 exception=None
    ):
        self.current_boot = current_boot
        self.next_boot = next_boot
        self.boot_order = boot_order
        self.entries = entries
        self._exception = exception

    def __call__(self):
        """Tested functions call existing object instead of creating one.

        The object is expected to be instantiated already when mocking
        so tested functions are not creating new object but are calling already
        the created one. From the point of the tested code, the behaviour is
        same now.
        """
        if not self._exception:
            return self
        raise self._exception


class TestEFIChecks(unittest.TestCase):

    def _gen_version(major, minor):
        return namedtuple("Version", ["major", "minor"])(major, minor)

    def _check_efi_detection_log(self, efi_detected=True):
        if efi_detected:
            self.assertFalse("BIOS detected." in checks.logger.debug_msgs)
            self.assertTrue("EFI detected." in checks.logger.debug_msgs)
        else:
            self.assertTrue("BIOS detected." in checks.logger.debug_msgs)
            self.assertFalse("EFI detected." in checks.logger.debug_msgs)

    @unit_tests.mock(grub, "is_efi", lambda: False)
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(checks.system_info, "version", _gen_version(6, 10))
    def test_check_efi_bios_detected(self):
        checks.check_efi()
        self.assertFalse(checks.logger.critical_msgs)
        self._check_efi_detection_log(False)

    def _check_efi_critical(self, critical_msg):
        self.assertRaises(SystemExit, checks.check_efi)
        self.assertEqual(len(checks.logger.critical_msgs), 1)
        self.assertTrue(critical_msg in checks.logger.critical_msgs)
        self._check_efi_detection_log(True)

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(6, 10))
    def test_check_efi_old_sys(self):
        self._check_efi_critical("The conversion with EFI is supported only for systems from major version 7.")

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: False)
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: not x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked(exception=grub.BootloaderError("errmsg")))
    def test_check_efi_efi_detected_without_efibootmgr(self):
        self._check_efi_critical("Install efibootmgr to continue converting EFI system.")

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: False)
    @unit_tests.mock(checks.system_info, "arch", "aarch64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked(exception=grub.BootloaderError("errmsg")))
    def test_check_efi_efi_detected_non_intel(self):
        self._check_efi_critical("Only x86_64 systems are supported for EFI conversions.")

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: True)
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked(exception=grub.BootloaderError("errmsg")))
    def test_check_efi_efi_detected_secure_boot(self):
        self._check_efi_critical("The conversion with secure boot is currently not supported.")
        self.assertTrue("Secure boot detected." in checks.logger.debug_msgs)

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: False)
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked(exception=grub.BootloaderError("errmsg")))
    def test_check_efi_efi_detected_bootloader_error(self):
        self._check_efi_critical("errmsg")

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: False)
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked(current_boot="0002"))
    def test_check_efi_efi_detected_nofile_entry(self):
        checks.check_efi()
        self._check_efi_detection_log()
        warn_msg = (
            "The current EFI bootloader '0002' is not referring to any"
            " binary EFI file located on ESP."
        )
        self.assertTrue(warn_msg in checks.logger.warning_msgs)

    @unit_tests.mock(grub, "is_efi", lambda: True)
    @unit_tests.mock(grub, "is_secure_boot", lambda: False)
    @unit_tests.mock(checks.system_info, "arch", "x86_64")
    @unit_tests.mock(checks.system_info, "version", _gen_version(7, 9))
    @unit_tests.mock(checks, "logger", GetLoggerMocked())
    @unit_tests.mock(os.path, "exists", lambda x: x == "/usr/sbin/efibootmgr")
    @unit_tests.mock(grub, "EFIBootInfo", EFIBootInfoMocked())
    def test_check_efi_efi_detected_ok(self):
        checks.check_efi()
        self._check_efi_detection_log()
        self.assertEqual(len(checks.logger.warning_msgs), 0)
