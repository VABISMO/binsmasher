# MITRE CVE Submission Report — BinSmasher CVE Auditor v3
Generated: 2026-04-05T22:07:27.905488+00:00
Scope: CONFIRMED + High/Critical findings only
---

## CVE-PENDING-AUDIT-0001  —  BufferOverflow in vuln_test via gets()

### Vulnerability Description
Unbounded stack buffer overflow via gets(). Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x401252. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **9.5** (CRITICAL)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-120: Unbounded stack buffer overflow via gets()

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: gets`
- `Call sites: 0x401252`
- `Disasm context: 401252:	e8 79 fe ff ff       	call   4010d0 <gets@plt>`
- `Disasm context: 401257:	90                   	nop`
- `Disasm context: 401258:	c9                   	leave`
- `Disasm context: 401259:	c3                   	ret`
- `Disasm context: 000000000040125a <main>:`
- `Disasm context: 40125a:	f3 0f 1e fa          	endbr64`
- `Disasm context: 40125e:	55`
- `[Taint] Call path: gets`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Replace gets() with fgets(buf, sizeof(buf), stdin). Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-120 Reference](https://cwe.mitre.org/data/definitions/120.html)

---

## CVE-PENDING-AUDIT-0002  —  FormatString in vuln_test via printf()

### Vulnerability Description
Uncontrolled format string — memory read/write primitive. Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x401205. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **9.5** (CRITICAL)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-134: Uncontrolled format string — memory read/write primitive

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: printf`
- `Call sites: 0x401205`
- `Disasm context: 401205:	e8 b6 fe ff ff       	call   4010c0 <printf@plt>`
- `Disasm context: 40120a:	90                   	nop`
- `Disasm context: 40120b:	c9                   	leave`
- `Disasm context: 40120c:	c3                   	ret`
- `Disasm context: 000000000040120d <network_recv>:`
- `Disasm context: 40120d:	f3 0f 1e fa          	endbr64`
- `Disasm context: 401211:	55`
- `[Taint] Call path: main → vulnerable_copy → printf`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Always pass a literal format string: printf("%s", user_input). Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-134 Reference](https://cwe.mitre.org/data/definitions/134.html)

---

## CVE-PENDING-AUDIT-0003  —  BufferOverflow in vuln_test via recv()

### Vulnerability Description
Network recv() without size validation — heap overflow. Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x40123e. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **8.8** (HIGH)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-122: Network recv() without size validation — heap overflow

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: recv`
- `Call sites: 0x40123e`
- `Disasm context: 401232:	ba 00 04 00 00       	mov    $0x400,%edx`
- `Disasm context: 401237:	89 c7                	mov    %eax,%edi`
- `Disasm context: 401239:	b8 00 00 00 00       	mov    $0x0,%eax`
- `Disasm context: 40123e:	e8 4d fe ff ff       	call   401090 <recv@plt>`
- `Disasm context: 401243:	48 8d 85 70 ff ff ff 	lea    -0x90(%rbp),%rax`
- `Disasm context: 40124a:	48 89 c7             	mov    %rax,%rdi`
- `Disasm context: 40124d:	b8 00 00 00 00       	mov    $0x0,%eax`
- `Disasm context: 401252:	e8 79 fe ff ff       	call   4010d0`
- `[Taint] Call path: recv`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Always pass sizeof(buf) as the length argument to recv(). Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-122 Reference](https://cwe.mitre.org/data/definitions/122.html)

---

## CVE-PENDING-AUDIT-0004  —  BufferOverflow in vuln_test via sprintf()

### Vulnerability Description
Unchecked sprintf — format/buffer overflow. Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x40129f. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **7.2** (HIGH)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-134: Unchecked sprintf — format/buffer overflow

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: sprintf`
- `Call sites: 0x40129f`
- `Disasm context: 401294:	48 89 d6             	mov    %rdx,%rsi`
- `Disasm context: 401297:	48 89 c7             	mov    %rax,%rdi`
- `Disasm context: 40129a:	b8 00 00 00 00       	mov    $0x0,%eax`
- `Disasm context: 40129f:	e8 3c fe ff ff       	call   4010e0 <sprintf@plt>`
- `Disasm context: 4012a4:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax`
- `Disasm context: 4012ab:	48 83 c0 08          	add    $0x8,%rax`
- `Disasm context: 4012af:	48 8b 00             	mov    (%rax),%rax`
- `Disasm context: 4012b2:	48 89 c7             	mov    %ra`
- `[Taint] Call path: main → sprintf`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Replace sprintf() with snprintf() with explicit size. Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-134 Reference](https://cwe.mitre.org/data/definitions/134.html)

---

## CVE-PENDING-AUDIT-0005  —  BufferOverflow in vuln_test via strcpy()

### Vulnerability Description
Unchecked string copy — potential stack overflow. Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x4011f4. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **7.8** (HIGH)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-120: Unchecked string copy — potential stack overflow

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: strcpy`
- `Call sites: 0x4011f4`
- `Disasm context: 4011ea:	48 8d 45 c0          	lea    -0x40(%rbp),%rax`
- `Disasm context: 4011ee:	48 89 d6             	mov    %rdx,%rsi`
- `Disasm context: 4011f1:	48 89 c7             	mov    %rax,%rdi`
- `Disasm context: 4011f4:	e8 a7 fe ff ff       	call   4010a0 <strcpy@plt>`
- `Disasm context: 4011f9:	48 8d 45 c0          	lea    -0x40(%rbp),%rax`
- `Disasm context: 4011fd:	48 89 c7             	mov    %rax,%rdi`
- `Disasm context: 401200:	b8 00 00 00 00       	mov    $0x0,%eax`
- `Disasm context: 401205:	e8 b6 fe ff ff       	call   4010c0`
- `[Taint] Call path: main → vulnerable_copy → strcpy`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Replace strcpy() with strlcpy() or snprintf(). Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-120 Reference](https://cwe.mitre.org/data/definitions/120.html)

---

## CVE-PENDING-AUDIT-0006  —  CommandInjection in vuln_test via system()

### Vulnerability Description
system() call — OS command injection if input reaches it. Found in binary 'vuln_test' (SHA-256: 10f89596e176b163f0d7bc8c9596d5d4bd90363788bdea46730776e854199956) at address 0x4012c4. Binary protections: NX=False, PIE=False, Canary=False, RELRO=None.

### CVSS 3.1
- Base Score: **9.5** (CRITICAL)
- Vector:     `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Attack Vector: NETWORK

### Weakness Classification
- CWE-78: system() call — OS command injection if input reaches it

### Affected Product
- Binary: `vuln_test`

### Evidence
- `Imported symbol: system`
- `Call sites: 0x4012c4`
- `Disasm context: 4012c9:	b8 00 00 00 00       	mov    $0x0,%eax`
- `Disasm context: 4012ce:	c9                   	leave`
- `Disasm context: 4012cf:	c3                   	ret`
- `Disasm context: Disassembly of section .fini:`
- `Disasm context: 00000000004012d0 <_fini>:`
- `Disasm context: 4012d0:	f3 0f 1e`
- `[Taint] Call path: main → system`
- `[Taint] Register analysis: Could not determine arg source — conservative PROBABLE`
- `[Taint] Direct taint path found and register args appear user-controlled`

### Solution
Avoid system(). Use execve() with a fixed path and validated args. Compiler hardening: enable NX/DEP (-Wl,-z,noexecstack), compile with -fPIE -pie, enable stack canaries (-fstack-protector-strong), enable RELRO (-Wl,-z,relro,-z,now).

### References
- [MITRE CVE Pending](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING)
- [CWE-78 Reference](https://cwe.mitre.org/data/definitions/78.html)

---
