# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, comm_dissector scripts.

    This test verifies functions of the script by using
    `tshark`, command line Wireshark utility.
"""

# Copyright (C) 2023 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2023 Original Gangsters <https://dji-rev.slack.com/>
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import subprocess
import os
import re
import sys
import struct
import time
import datetime
import pytest

LOGGER = logging.getLogger(__name__)

pckt_mavic_air_fcc = [0x55, 0x17, 0x04, 0x38, 0x02, 0x0e, 0x1d, 0x00, 0x40, 0x07, 0x30, 0x55, 0x53, 0x00, 0x00, 0x55, 0x53, 0x00, 0x00, 0x01, 0x00, 0xfe, 0x5d]
# M600 Pro ESC bus: FC throttle request (DUML v0, captured from the A3 FC m0306 v01.00.01.65 running in an emulator);
# ESC telemetry response (DUML v0) and ESC Mute Set request (DUML v1), both constructed from the firmware code, not captured
pckt_m600_esc_throttle = [0x55, 0x16, 0x00, 0x9d, 0xa0, 0x00, 0x00, 0x03, 0xac, 0x03, 0xac, 0x03, 0xac, 0x03, 0xac, 0x03, 0xac, 0x03, 0xac, 0x03, 0x4c, 0x78]
pckt_m600_esc_telemetry = [0x55, 0x1c, 0x00, 0x7a, 0xa0, 0x01, 0x02, 0x00, 0x62, 0x09, 0x66, 0x00, 0x20, 0x00, 0xb8, 0x0b, 0x14, 0x05, 0xf6, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xfa, 0x77]
pckt_m600_esc_mute = [0x55, 0x0d, 0x04, 0x33, 0x03, 0x4c, 0x10, 0x00, 0x40, 0x0c, 0xb0, 0xb4, 0xf1]
pckt_mini_2_fcc = [0x55, 0x18, 0x04, 0x20, 0x02, 0x09, 0x00, 0x00, 0x40, 0x09, 0x27, 0x00, 0x02, 0x48, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x81, 0x1f]

def write_one_packet_pcap(fname, userdlt, data):
    with open(fname, "wb") as out:
        out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            65535,        # max length of captured packets, in octets
            147+userdlt, # data link type (DLT) - USER_0
        ))

        dtime = datetime.datetime.now()
        timestamp = int(time.mktime(dtime.timetuple()))
        out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            dtime.microsecond, # timestamp microseconds
            len(data),        # number of octets of packet saved in file
            len(data),        # actual length of packet
        ))
        out.write(data)

def run_comm_dissector_tshark_show(cmd, inp_file, proto_name, pkt_cmd, env=None, expect_texts=()):
    command = [cmd, '-r', inp_file, '-V']
    LOGGER.info(' '.join(command))
    prc_result = subprocess.run(command, env=env, capture_output=True)
    assert prc_result.returncode == 0
    # Check if protocol name is found in tshark output (protocol was recognized)
    assert str(prc_result.stdout).find(proto_name) > 0
    # Check if command from the packet is found in tshark output (packet header was dissected)
    match = re.search(r'\s+Cmd: [A-Za-z0-9 \//,.-]+ [\(]0x([0-9a-f]+)[\)]', str(prc_result.stdout), re.IGNORECASE)
    assert match
    assert int(match.group(1), 16) == pkt_cmd
    # Check if payload fields were dissected
    for text in expect_texts:
        assert str(prc_result.stdout).find(text) > 0
    assert str(prc_result.stdout).find("Lua Error") < 0

def case_comm_dissector_tshark_show(pcap_file, userdlt, proto_name, pckt, env=None, expect_texts=()):
    pkt_protover = (pckt[2] >> 2)
    # DUML v0 packets have the command at offset 4, v1 at offset 10
    pkt_cmd = int(pckt[4]) if pkt_protover == 0 else int(pckt[10])
    write_one_packet_pcap(pcap_file, userdlt, bytearray(pckt))
    run_comm_dissector_tshark_show("tshark", str(pcap_file), proto_name, pkt_cmd, env=env, expect_texts=expect_texts)

@pytest.mark.comm
def test_comm_dissector_tshark_show(tmp_path):
    """ Test dissecting a packet with Wiresharks tshark.
    """
    test_env = os.environ.copy()
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-mavair.pcap", 3, "DJI_DUMLv1", pckt_mavic_air_fcc, env=test_env)
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-mini2.pcap",  3, "DJI_DUMLv1", pckt_mini_2_fcc, env=test_env)
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-m600esc1.pcap", 3, "DJI_DUMLv1", pckt_m600_esc_throttle, env=test_env,
      expect_texts=("Poll Index: 3", "Pulse Width (us): 940"))
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-m600esc2.pcap", 3, "DJI_DUMLv1", pckt_m600_esc_telemetry, env=test_env,
      expect_texts=("ESC Index: 2", "Temperature (C): 32", "PPM Received (us): 1300"))
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-m600esc3.pcap", 3, "DJI_DUMLv1", pckt_m600_esc_mute, env=test_env)
