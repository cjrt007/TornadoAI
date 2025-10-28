"""Security tool catalog and helper utilities."""
from __future__ import annotations

from typing import Dict, List

from .models import ToolDescriptor


_TOOL_COMMANDS: List[ToolDescriptor] = [
    ToolDescriptor(
        name="nmap",
        category="Network Scanning",
        description="Network mapper for port scanning and service enumeration.",
        command="nmap -sV {target}",
    ),
    ToolDescriptor(
        name="nuclei",
        category="Vulnerability Scanning",
        description="Template based vulnerability scanner covering OWASP and SANS categories.",
        command="nuclei -u {target}",
    ),
    ToolDescriptor(
        name="sqlmap",
        category="Database Testing",
        description="Automated SQL injection and database takeover tool.",
        command="sqlmap -u {target}",
    ),
    ToolDescriptor(
        name="jadx",
        category="Mobile Reverse Engineering",
        description="Dex to Java decompiler for Android applications.",
        command="jadx {artifact}",
        documentation="https://github.com/skylot/jadx",
    ),
    ToolDescriptor(
        name="apktool",
        category="Mobile Reverse Engineering",
        description="Utility for reverse engineering Android APK files.",
        command="apktool d {artifact}",
    ),
    ToolDescriptor(
        name="MobSF",
        category="Mobile Security Testing",
        description="Mobile Security Framework for automated static and dynamic analysis.",
        command="mobsf --scan {artifact}",
    ),
    ToolDescriptor(
        name="frida",
        category="Dynamic Instrumentation",
        description="Dynamic instrumentation toolkit for developers and reverse engineers.",
        command="frida -U -f {package} --no-pause",
    ),
    ToolDescriptor(
        name="objection",
        category="Dynamic Instrumentation",
        description="Runtime mobile exploration toolkit powered by Frida.",
        command="objection -g {package} explore",
    ),
    ToolDescriptor(
        name="reflutter",
        category="Mobile Reverse Engineering",
        description="Toolkit to aid Flutter application reversing.",
        command="reflutter {artifact}",
    ),
    ToolDescriptor(
        name="dirb",
        category="Web Content Discovery",
        description="Web content scanner for brute forcing directories and files.",
        command="dirb {target}",
    ),
    ToolDescriptor(
        name="whatweb",
        category="Reconnaissance",
        description="Web scanner identifying technologies used by websites.",
        command="whatweb {target}",
    ),
    ToolDescriptor(
        name="ffuf",
        category="Web Fuzzing",
        description="Fast web fuzzer written in Go.",
        command="ffuf -u {target}/FUZZ -w {wordlist}",
    ),
    ToolDescriptor(
        name="wfuzz",
        category="Web Fuzzing",
        description="Flexible web application fuzzer.",
        command="wfuzz -c -z file,{wordlist} {target}",
    ),
    ToolDescriptor(
        name="masscan",
        category="Network Scanning",
        description="Massive asynchronous TCP port scanner.",
        command="masscan {target} -p0-65535",
    ),
    ToolDescriptor(
        name="burpsuite",
        category="Web Proxy",
        description="Interactive web security testing platform.",
        command="burpsuite",
    ),
    ToolDescriptor(
        name="xcode-select",
        category="iOS Penetration Testing",
        description="Placeholder representing required Xcode command line tools.",
        command="xcode-select --install",
        documentation="https://developer.apple.com/xcode/resources/",
    ),
    ToolDescriptor(
        name="objection-ios",
        category="iOS Penetration Testing",
        description="Objection toolkit usage for iOS with Frida gadgets.",
        command="objection --ios explore",
    ),
    ToolDescriptor(
        name="idb",
        category="iOS Penetration Testing",
        description="iOS app penetration testing tool.",
        command="idb --list-apps",
    ),
]


def list_tools() -> List[ToolDescriptor]:
    """Return the catalog of supported tools."""

    return list(_TOOL_COMMANDS)


def tool_lookup() -> Dict[str, ToolDescriptor]:
    """Return a mapping keyed by tool name for easy lookup."""

    return {tool.name: tool for tool in _TOOL_COMMANDS}
