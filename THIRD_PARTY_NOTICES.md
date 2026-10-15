# Third-party notices

Dependencies are pinned in go.mod/go.sum and resolved using Go's checksum database.

| Module | Use | License |
|---|---|---|
| github.com/zalando/go-keyring | OS credential-store adapter | MIT; portions Apache-2.0 |
| al.essio.dev/pkg/shellescape | Safe macOS security-tool stdin escaping | MIT |
| github.com/danieljoos/wincred | Windows Credential Manager | MIT |
| github.com/godbus/dbus/v5 | Linux Secret Service transport | BSD-2-Clause |
| golang.org/x/sys | Platform system calls | BSD-3-Clause |

Go's standard library/toolchain uses a BSD-style license, included as `dependency-licenses/go-standard-library-LICENSE`. The SPDX inventory contains the runtime-module union across all supported release targets; test-only transitive packages are excluded. Release packaging must include the dependency license texts from the exact resolved modules, not only this summary.

The macOS adapter writes secrets to `/usr/bin/security -i` through standard input; they are not passed in process arguments. Its output and errors are not printed with credential content. No dependency is given service or deployment credentials.
