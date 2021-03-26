# -*- coding: utf-8 -*-
#
# Copyright(C) 2021 Red Hat, Inc.
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

import logging
import os
import re
import shutil

from convert2rhel import systeminfo, utils

logger = logging.getLogger(__name__)

RHEL_EFIDIR_CANONICAL_PATH = "/boot/efi/EFI/redhat/"
"""The canonical path to the default efi directory on for RHEL system."""

RHEL_EFIBIN_CANONICAL_DEFAULT_PATH = os.path.join(RHEL_EFIDIR_CANONICAL_PATH, "shimx64.efi")
"""The canonical path to the default RHEL EFI binary."""


class BootloaderError(Exception):
    """The generic error related to this module."""

    def __init__(self, message):
        super(BootloaderError, self).__init__(message)
        self.message = message

class UnsupportedEFIConfiguration(BootloaderError):
    """Raised when the bootloader EFI configuration seems unsupported.

    E.g. when we expect the ESP is mounted to /boot/efi but it is not.
    """
    pass


class NotUsedEFI(BootloaderError):
    """Raised when expected a use on EFI only but BIOS is detected."""
    pass


class InvalidPathEFI(BootloaderError):
    """Raise when path to EFI is invalid."""
    pass


def is_uefi():
    """Return True if UEFI is used."""
    return True if os.path.exists("/sys/firmware/efi") else False


def is_secure_boot():
    """Return True if the secure boot is enabled."""
    if not is_uefi:
        return False
    try:
        stdout, ecode = utils.run_subprocess("mokutil --sb-state", print_output=False)
    except OSError:
        return False
    if ecode or "enabled" not in stdout:
        return False
    return True


def _log_critical_error(title):
        logger.critical(
            "%s\n"
            "The migration of the bootloader setup was not successful.\n"
            "Do not reboot your machine before the manual check of the\n"
            "bootloader configuration. Ensure grubenv and grub.cfg files\n"
            "are present inside the /boot/efi/EFI/redhat/ directory and\n"
            "the new bootloader entry for Red Hat Enterprise Linux exist\n"
            "(check `efibootmgr -v` output).\n"
            "The entry should point to '\\EFI\\redhat\\shimx64.efi'." % title
        )


def _get_partition(directory):
    """Return the disk partition for the specified directory.

    Raise BootloaderError if the partition cannot be detected.
    """
    stdout, ecode = utils.run_subprocess("/usr/sbin/grub2-probe --target=device /boot", print_output=False)
    if ecode or not stdout:
        logger.error("grub2-probe ended with non-zero exit code.\n%s" % stdout)
        raise BootloaderError("Cannot get device information for %s." % directory)
    return stdout.strip()


def get_boot_partition():
    """Return the disk partition with /boot present.

    Raise BootloaderError if the partition cannot be detected.
    """
    return _get_partition("/boot")


def get_efi_partition():
    """Return the EFI System Partition (ESP).

    Raise NotUsedEFI if UEFI is not detected.
    Raise UnsupportedEFIConfiguration when ESP is not mounted where expected.
    Raise BootloaderError if the partition cannot be obtained from GRUB.
    """
    if not is_uefi:
        raise NotUsedEFI("Cannot get ESP when BIOS is used.")
    if not os.path.exists("/boot/efi") or not os.path.ismount("/boot/efi"):
        raise UnsupportedEFIConfiguration(
            "The EFI has been detected but the ESP is not mounted"
            " in /boot/efi as required."
        )
    return _get_partition("/boot/efi")


def _get_blk_device(device):
    """Get the block device.

    In case of the block device itself (e.g. /dev/sda) returns just the block
    device. For a partition, returns its block device:
        /dev/sda  -> /dev/sda
        /dev/sda1 -> /dev/sda

    Raise ValueError on empty / None device
    Raise the BootloaderError when cannot get the block device.
    """
    if not device:
        raise ValueError("The device must be speficied.")
    stdout, ecode = utils.run_subprocess("lsblk -spnlo name %s" % device, print_output=False)
    if ecode:
        logger.error("Cannot get the block device for '%s'." % device)
        logger.debug("lsblk ... output:\n-----\n%s\n-----" % stdout)
        raise BootloaderError("Cannot get the block device")
        
    return stdout.strip().split("\n")[-1].strip()


def get_device_number(device):
    """Return dict with 'major' and 'minor' number of specified device/partition.

    Raise ValueError on empty / None device
    """
    if not device:
        raise ValueError("The device must be specified.")
    stdout, ecode = utils.run_subprocess("lsblk -spnlo MAJ:MIN %s" % device, print_output=False)
    if ecode:
        logger.error("Cannot get information about the '%s' device." % device)
        logger.debug("lsblk ... output:\n-----\n%s\n-----" % stdout)
        return None
    # for partitions the output contains multiple lines (for the partition
    # and all parents till the devices itself). We want maj:min number just
    # for the specified device/partition, so take the first line only
    majmin = stdout.split("\n")[0].strip().split(":")
    return {"major": int(majmin[0]), "minor": int(majmin[1])}


def get_grub_device():
    """Get the block device where GRUB is located.

    We assume GRUB is on the same device as /boot (or ESP).
    Raise UnsupportedEFIConfiguration when UEFI detected but ESP
          has not been discovered.
    Raise BootloaderError if the block device cannot be obtained.
    """
    # in 99% it should not matter to distinguish between /boot and /boot/efi,
    # but seatbelt is better
    partition = get_efi_partition() if is_uefi() else get_boot_partition()
    return _get_blk_device(partition)


class EFIBootLoader(object):
    """Representation of an EFI boot loader entry"""

    def __init__(self, boot_number, label, active, efi_bin_source):
        self.boot_number = boot_number
        """Expected string, e.g. '0001'. """

        self.label = label
        """Label of the EFI entry. E.g. 'Centos'"""

        self.active = active
        """True when the EFI entry is active (asterisk is present after the boot number)"""

        self.efi_bin_source = efi_bin_source
        """Source of the EFI binary.

        It could contain various values, e.g.:
            FvVol(7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1)/FvFile(462caa21-7614-4503-836e-8ab6f4662331)
            HD(1,GPT,28c77f6b-3cd0-4b22-985f-c99903835d79,0x800,0x12c000)/File(\EFI\redhat\shimx64.efi)
            PciRoot(0x0)/Pci(0x2,0x3)/Pci(0x0,0x0)N.....YM....R,Y.
        """


class EFIBootInfo(object):
    """Data about the current EFI boot configuration.

    Raise BootloaderError when cannot obtain info about the EFI configuration.
    Raise NotUsedEFI when BIOS is detected.
    Raise UnsupportedEFIConfiguration when ESP is not mounted where expected.
    """

    def __init__(self):
        if not is_uefi():
            raise NotUsedEFI("Cannot collect data about EFI on BIOS system.")
        brief_stdout, ecode = utils.run_subprocess("/usr/sbin/efibootmgr", print_output=False)
        verbose_stdout, ecode2 = utils.run_subprocess("/usr/sbin/efibootmgr -v", print_output=False)
        if ecode or ecode2:
            raise BootloaderError("Cannot get information about EFI boot entries.")

        self.current_boot = None
        """The boot number (str) of the current boot."""
        self.next_boot = None
        """The boot number (str) of the next boot - if set."""
        self.boot_order = None
        """The tuple of the EFI boot loader entries in the boot order."""
        self.entries = {}
        """The EFI boot loader entries {'boot_num': EFIBootLoader}"""
        self.efi_partition = get_efi_partition()
        """The EFI System Partition (ESP)"""

        self._parse_efi_boot_entries(brief_stdout, verbose_stdout)
        self._parse_current_boot(brief_stdout)
        self._parse_boot_order(brief_stdout)
        self._parse_next_boot(brief_stdout)

    def _parse_efi_boot_entries(self, brief_data, verbose_data):
        """Return dict of EFI boot loader entries: {"<boot_number>": EFIBootLoader}"""
        self.entries = {}
        regexp_entry = re.compile(r"^Boot(?P<bootnum>[0-9]+)[\s*]\s*(?P<label>[^\s].*)$")
        for line in brief_data.split("\n"):
            match = regexp_entry.match(line)
            if not match:
                continue
            # find the source in verbose data
            vline = [i for i in verbose_data.split("\n") if i.strip().startswith(line)][0]
            efi_bin_source = vline[len(line):].strip()

            self.entries[match.group("bootnum")] = EFIBootLoader(
                boot_number=match.group("bootnum"),
                label=match.group("label"),
                active="*" in line,
                efi_bin_source=efi_bin_source,
            )
        if not self.entries:
            # it's not expected that no entry exists
            raise BootloaderError("EFI: Cannot detect EFI bootloaders.")

    def _parse_current_boot(self, data):
        # e.g.: BootCurrent: 0002
        for line in data.split("\n"):
            if line.startswith("BootCurrent:"):
                self.current_boot = line.split(":")[1].strip()
                return
        raise BootloaderError("EFI: Cannot detect current boot number.")

    def _parse_next_boot(self, data):
        # e.g.:  BootCurrent: 0002
        for line in data.split("\n"):
            if line.startswith("BootNext:"):
                self.next_boot = line.split(":")[1].strip()
                return
        logger.debug("EFI: the next boot is not set.")

    def _parse_boot_order(self, data):
        # e.g.:  BootOrder: 0001,0002,0000,0003
        for line in data.split("\n"):
            if line.startswith("BootOrder:"):
                self.boot_order = tuple(line.split(":")[1].strip().split(","))
                return
        raise BootloaderError("EFI: Cannot detect current boot order.")


def canonical_path_to_efi_format(canonical_path):
    """Transform the canonical path to the EFI format.

    e.g. /boot/efi/EFI/redhat/shimx64.efi -> \\EFI\\redhat\\shimx64.efi
    (just single backslash; so the strin needs to be put into apostrophes
    when used for /usr/sbin/efibootmgr cmd)

    The path has to start with /boot/efi otherwise the path is invalid for EFI.

    Raise ValueError on invalid EFI path.
    """
    if not canonical_path.startswith("/boot/efi"):
        raise ValueError("Invalid path to the EFI binary: %s" % canonical_path)
    return canonical_path[9:].replace("/", "\\")


def _copy_grub_files():
    """Copy grub files from centos dir to the /boot/efi/EFI/redhat/ dir.

    The grub.cfg, grubenv, ... files are not present in the redhat directory
    after the conversion on centos system. These files are usually created
    during the OS installation by anaconda and have to be present in the
    redhat directory after the conversion.

    The copy from the centos directory should be ok. In case of the conversion
    from OL, the redhat directory is already used.

    Return False when any required file has not been copied or is missing.
    """
    if systeminfo.system_info.id != "centos":
        logger.debug("Skipping the copy of grub files - related only for centos.")
        return

    logger.info("Copy the GRUB2 configuration files to the new EFI directory.")
    src_efidir = "/boot/efi/EFI/centos/"
    flag_ok = True
    required_files = ["grubenv", "grub.cfg"]
    all_files = required_files + ["user.cfg"]
    for filename in all_files:
        src_path = os.path.join(src_efidir, filename)
        dst_path = os.path.join(RHEL_EFIDIR_CANONICAL_PATH, filename)
        if os.path.exists(dst_path):
            logger.info("The %s file already exists. Copying skipped." % dst_path)
            continue
        if not os.path.exists(src_path):
            if filename in required_files:
                # without the required files user should not reboot the system
                logger.error(
                    "Cannot find the original file required for the proper"
                    " configuration: %s" % src_path)
                flag_ok = False
            continue
        logger.info("Copying '%s' to '%s'" % (src_path, dst_path))
        try:
            shutil.copy2(src_path, dst_path)
        except IOError as err:
                # FIXME: same as fixme above
                logger.error("I/O error(%s): %s" % (err.errno, err.strerror))
                flag_ok = False
    return flag_ok


def _replace_efi_boot_entry(efibootinfo):
    """Replace the current bootloader entry with the RHEL one.

    The current EFI bootloader entry points still to the original path
    (which could be invalid already) and label contains still the original
    OS name. The new entry will point to expected path and will contain
    the expected RHEL label.
    """
    # This should work fine, unless people would like to use something "custom".
    label = "Red Hat Enterprise Linux %s" % str(systeminfo.system_info.version.major)
    logger.info("Create the '%s' EFI bootloader entry." % label)
    try:
        dev_number = get_device_number(efibootinfo.efi_partition)
        blk_dev = get_grub_device
    except BootloaderError:
        raise BootloaderError("Cannot get required information about the EFI partition.")
    logger.debug("Block device: %s" % str(blk_dev))
    logger.debug("ESP device number: %s" % str(dev_number))

    efi_path = canonical_path_to_efi_format(RHEL_EFIBIN_CANONICAL_DEFAULT_PATH)
    cmd_fmt = "/usr/sbin/efibootmgr -c -d %s -p %s -l '%s' -L '%s'"
    cmd_params = (blk_dev, dev_number["minor"], efi_path, label)

    stdout, ecode = utils.run_subprocess(cmd_fmt % cmd_params, print_output=False)
    if ecode:
        logger.debug("efibootmgr output:\n-----\n%s\n-----" % stdout)
        raise BootloaderError(
            "Cannot create the new EFI bootloader entry for RHEL."
        )
    # remove the original EFI bootloader
    # TODO(pstodulk): do not remove the original entry if do not point to
    # a default /efidir/efibin...
    logger.info("Remove the original EFI bootloader entry.")
    _, ecode = utils.run_subprocess("/usr/sbin/efibootmgr -Bb %s" % efibootinfo.current_boot, print_output=False)
    if ecode:
        # this is not a critical issue; the entry will be even removed
        # automatically if it is invalid (points to non-existing efibin)
        logger.warning("Cannot remove the original EFI bootloader entry.")

    # check that our entry really exists, if yes, it will be default for sure
    logger.info("Check the new EFI bootloader.")
    new_efibootinfo = EFIBootInfo()
    new_boot_entry = None
    for i in new_efibootinfo.entries.values():
        if i.label == label and efi_path in i.efi_bin_source:
            new_boot_entry = i
    if not new_boot_entry:
        raise BootloaderError("Cannot get the boot number of the new EFI bootloader entry.")


def _remove_efi_centos():
    """Remove the /boot/efi/EFI/centos directory when no efi files remains.

    The centos directory after the conversion contains usually just grubenv,
    grub.cfg, .. files only. Which we copy into the redhat directory. If no
    other efi files are present, we can remove this dir. However, if additional
    efi files are present, we should keep the directory for now, until we
    deal with it.
    """
    if systeminfo.system_info.id != "centos":
        # nothing to do
        return
    # TODO: remove original centos directory if no efi bin is present
    logger.warning(
        "The original /boot/efi/EFI/centos directory is kept."
        " Remove the directory manually after you check it's not needed"
        " anymore."
    )


def post_ponr_set_efi_configuration():
    """Configure GRUB after the conversion.

    Original setup points to \\EFI\\centos\\shimx64.efi but after
    the conversion it should point to \\EFI\\redhat\\shimx64.efi. As well some
    files like grubenv, grub.cfg, ...  are not migrated by default to the
    new directory as these are usually created just during installation of OS.

    The current implementation ignores possible multi-boot installations.
    It expects just one installed OS. IOW, only the CurrentBoot entry is handled
    correctly right now. Other possible boot entries have to be handled manually
    if needed.

    Nothing happens on BIOS.
    """
    if not is_uefi():
        logger.info("The BIOS detected. Nothing to do.")
        return

    if not os.path.exists(RHEL_EFIBIN_CANONICAL_DEFAULT_PATH):
        # TODO: this could happen only if the shim package is not installed,
        # but it doesn't have to. In such a case the grubx64.efi should be used
        # (which is always present)
        _log_critical_error("The expected EFI binary does not exist: %s" % RHEL_EFIBIN_CANONICAL_DEFAULT_PATH)
    if not os.path.exists("/usr/sbin/efibootmgr"):
        _log_critical_error("The /usr/sbin/efibootmgr utility is not installed.")


    # related just for centos. check inside
    if not _copy_grub_files():
        _log_critical_error("Some GRUB files have not been copied to /boot/efi/EFI/redhat")
    _remove_efi_centos()

    try:
        # load the bootloader configuration NOW - after the grub files are copied
        logger.info("Load the bootloader configuration.")
        efibootinfo = EFIBootInfo()
        logger.info("Replace the current EFI bootloader entry with the RHEL one.")
        _replace_efi_boot_entry(efibootinfo)
    except BootloaderError as e:
        # TODO(pstodulk): originally we discussed it will be better to not use
        # the critical log, for the possibility the additional post converstion
        # actions could exist. However, I cannot come up with a good solution
        # without putting additional logic into the main(). So as currently 
        # this is the last action that could fail, I am just using this solution.
        _log_critical_error(e.message)
