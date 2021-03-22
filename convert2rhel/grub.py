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


def is_uefi():
    return True if os.path.exists("/sys/firmware/efi") else False

def _log_manual_action_msg():
    logger.error(
        "The migration of the bootloader setup was not successful."
        " Do not reboot your machine before the manual check of the"
        " bootloader configuration. Probably the manual creation"
        " of the new bootloader entry is required for '\\EFI\\redhat\\shimx64.efi'."
    )


def _get_partition(directory):
    """Return the disk partition for the specified directory.

    In case the partition cannot be detected, return None.
    """
    stdout, ecode = utils.run_subprocess("/usr/sbin/grub2-probe --target=device /boot", print_output=False)
    if ecode or not stdout:
        logging.error("Cannot get device information for %s." % directory)
        return None
    return stdout.strip()


def get_boot_partition():
    """Return the disk partition with /boot present."""
    return _get_partition("/boot")


def get_efi_partition():
    """Return the EFI System Partition (ESP) or None."""
    if not is_uefi:
        logger.warning("The system is not using EFI.")
        return None
    if not os.path.exists("/boot/efi") or not os.path.ismount("/boot/efi"):
        logger.warning(
            "The EFI has been detected but the EFI partition is not mounted"
            " in /boot/efi as required."
        )
        return None
    return _get_partition("/boot/efi")


def get_blk_device(device):
    """Get the block device.

    In case of the block device itself (e.g. /dev/sda) returns just the block
    device. For a partition, returns its block device:
        /dev/sda  -> /dev/sda
        /dev/sda1 -> /dev/sda
    """
    stdout, ecode = utils.run_subprocess("lsblk -spnlo name %s" % device, print_output=False)
    if ecode:
        logger.warning("Cannto get the block device for '%s'." % device)
        return None
    return stdout.strip().split("\n")[-1].strip()


def get_maj_min_dev_number(device):
    """Return dict with 'major' and 'minor' number of specified device/partition."""
    if not device:
        logger.error("get_maj_min_dev_number: the device is empty")
        return None
    stdout, ecode = utils.run_subprocess("lsblk -spnlo MAJ:MIN %s" % device, print_output=False)
    if ecode:
        logger.warning("Cannot get information about the %s device." % device)
        return None
    # for partitions output contains multiple lines (for the partition and all
    # parents till the devices itself. We want maj:min number just for the
    # specified device/partition, so take the first line only
    majmin = stdout.split("\n")[0].strip().split(":")
    return {"major": int(majmin[0]), "minor": int(majmin[1])}


def get_grub_device():
    """Get the block device where GRUB is located.

    We assume GRUB is on the same device as /boot (or ESP).
    """
    # in 99% it should not matter to distinguish between /boot and /boot/efi,
    # but seatbelt is better
    partition = get_efi_partition() if is_uefi() else get_boot_partition()
    return get_blk_device(partition) if partition else None


class EFIBootLoader(object):
    """Representation of an EFI boot loader entry"""

    def __init__(self, boot_number, label, active, efi_bin_source):
        # TODO(pstodulk): add type checks
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
    """Data about the current EFI boot configuration."""

    def __init__(self):
        # FIXME(pstodulk): what error should be raised here? or how to handle it?
        # FIXME(pstodulk): in general, check what error/warning/exception/... should
        # be used everywhere...
        if not is_uefi():
            logger.error("Cannot collect data about EFI on BIOS system.")
            return
        brief_stdout, ecode = utils.run_subprocess("/usr/sbin/efibootmgr", print_output=False)
        verbose_stdout, ecode2 = utils.run_subprocess("/usr/sbin/efibootmgr -v", print_output=False)
        if ecode or ecode2:
            logger.error("Cannot get information about EFI boot entries.")
            return

        self.current_boot = None
        """The boot number (str) of the current boot."""
        self.next_boot = None
        """The boot number (str) of the next boot - if set."""
        self.boot_order = None
        """The tuple of the EFI boot loader entries in the boot order."""
        self.entries = {}
        """The EFI boot loader entries {'boot_num': EFIBootLoader}"""

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

    def _parse_current_boot(self, data):
        # e.g.: BootCurrent: 0002
        for line in data.split("\n"):
            if line.startswith("BootCurrent:"):
                self.current_boot = line.split(":")[1].strip()
                return
        logger.error("Cannot detect current EFI boot.")

    def _parse_next_boot(self, data):
        # e.g.:  BootCurrent: 0002
        for line in data.split("\n"):
            if line.startswith("BootNext:"):
                self.next_boot = line.split(":")[1].strip()
                return

    def _parse_boot_order(self, data):
        # e.g.:  BootOrder: 0001,0002,0000,0003
        for line in data.split("\n"):
            if line.startswith("BootOrder:"):
                self.boot_order = tuple(line.split(":")[1].strip().split(","))
                return
        logger.error("Cannot detect current boot order.")


def canonical_path_to_efi_format(canonical_path):
    """Transform the canonical path to the EFI format.

    e.g. /boot/efi/EFI/redhat/shimx64.efi -> \\EFI\\redhat\\shimx64.efi
    (just single backslash; so the strin needs to be put into apostrophes
    when used for /usr/sbin/efibootmgr cmd)

    The path has to start with /boot/efi otherwise the path is invalid for EFI.
    """
    if not canonical_path.startswith("/boot/efi"):
        # FIXME: raise?
        logger.error("Invalid path to the EFI binary: %s" % canonical_path)
        return None
    return canonical_path[9:].replace("/", "\\")


def _copy_grub_files():
    """Copy grub files from centos dir to the /boot/efi/EFI/redhat/ dir.

    The grub.cfg, grubenv, ... files are not present in the redhat directory
    after the conversion on centos system. These files are usually created
    during the OS installation by anaconda and have to be present in the
    redhat directory after the conversion.

    The copy from the centos directory should be ok. In case of the conversion
    from OL, the redhat directory is already used.
    """
    if systeminfo.system_info.id != "centos":
        logger.debug("Skipping the copy of grub files - related only for centos.")
        return

    logger.info("Copy the GRUB2 configuration files to the new EFI directory.")
    src_efidir = "/boot/efi/EFI/centos/"
    for filename in ["grubenv", "grub.cfg"]:
        src_path = os.path.join(src_efidir, filename)
        dst_path = os.path.join(RHEL_EFIDIR_CANONICAL_PATH, filename)
        if os.path.exists(dst_path):
            logger.info("The %s file already exists. Copying skipped." % dst_path)
            continue
        if not os.path.exists(src_path):
            # FIXME: error?... what to do in such a case? it's definitely
            # unexpected and reboot could be fatal.
            logger.warning("Cannot find the original file: %s" % src_path)
            _log_manual_action_msg()
            continue
        logger.info("Copying '%s' to '%s'" % (src_path, dst_path))
        try:
            shutil.copy2(src_path, dst_path)
        except IOError as err:
                # FIXME: same as fixme above
                logger.warning("I/O error(%s): %s" % (err.errno, err.strerror))
                _log_manual_action_msg()


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
    dev_number = get_maj_min_dev_number(get_efi_partition())
    blk_dev = get_grub_device()
    efi_path = canonical_path_to_efi_format(RHEL_EFIBIN_CANONICAL_DEFAULT_PATH)
    cmd_fmt = "/usr/sbin/efibootmgr -c -d %s -p %s -l '%s' -L '%s'"
    logger.debug("Block device: %s" % str(blk_dev))
    logger.debug("Device number: %s" % str(dev_number))

    if not all([dev_number, blk_dev]):
        logger.warning("Cannot get required information about the EFI partition.")
        _log_manual_action_msg()
        return

    _, ecode = utils.run_subprocess(cmd_fmt % (blk_dev, dev_number["minor"], efi_path, label), print_output=False)
    if ecode:
        # FIXME: again the warning errror...
        logger.warning("Cannot create the new EFI bootloader entry for RHEL.")
        _log_manual_action_msg()
        return
    # remove the original EFI bootloader
    logger.info("Remove the original EFI bootloader entry.")
    _, ecode = utils.run_subprocess("/usr/sbin/efibootmgr -Bb %s" % efibootinfo.current_boot, print_output=False)
    if ecode:
        logger.warning("Cannot remove the original EFI bootloader entry. Remove it manually.")

    # check that our entry really exists, if yes, it will be default for sure
    logger.info("Check the new EFI bootloader is the default.")
    new_efibootinfo = EFIBootInfo()
    new_boot_entry = None
    for i in new_efibootinfo.entries.values():
        if i.label == label and efi_path in i.efi_bin_source:
            new_boot_entry = i
    if not new_boot_entry:
        logger.warning("Cannot get the boot number of the new EFI bootloader entry.")
        _log_manual_action_msg()
        return
    # everything is ok


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


def post_ponr_set_efi_configuration():
    """Configure GRUB after the conversion.

    Original setup points to \\EFI\\<orig_os>\\shimx64.efi but after
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
        return

    if not os.path.exists(RHEL_EFIBIN_CANONICAL_DEFAULT_PATH):
        # TODO: this could happen only if the shim package is not installed,
        # but it doesn't have to. In such a case the grubx64.efi should be used
        # (which is always present)
        logger.error("The expected EFI binary does not exist: %s" % RHEL_EFIBIN_CANONICAL_DEFAULT_PATH)
        return

    # related just for centos. check inside
    _copy_grub_files()
    _remove_efi_centos()

    # load the bootloader configuration NOW - after the grub files are copied
    # FIXME: what about problems?
    logger.info("Load the bootloader configuration.")
    efibootinfo = EFIBootInfo()

    logger.info("Replace the current EFI bootloader entry with the RHEL one.")
    # TODO(pstodulk): what to do with mutiple possible <source_os> EFI bootloaders?
    _replace_efi_boot_entry(efibootinfo)

