---
title: KeePass and KPScript (Windows)
description: Prepare the external programs required on Windows.
---

# KeePass and KPScript (Windows)

Windows requires two separate programs to access a KeePass database: **KeePass 2.x** and **KPScript**.

## Setup checklist

1. Download KeePass **2.x** from the [official download page](https://keepass.info/download.html).
2. Download a compatible **KPScript** version from the same official site.
3. Place `KPScript.exe` beside `KeePass.exe`. Keep the accompanying DLL files when using a portable version.
4. Set the path and run the diagnostic:

```sh
node src/cli/kp.ts config set keepass.kpscript "C:/path/to/KPScript.exe"
node src/cli/kp.ts doctor
```

::: tip Before the first command
If you have not created a configuration file, run `node src/cli/kp.ts config init` first.
:::

## Important notes

- These files are **not bundled or automatically downloaded** with keepass-agent.
- Do not commit KeePass binaries to the repository.
- KeePass is [GPL-licensed](https://keepass.info/help/v2/license.html); check the applicable license terms.
- On Linux, KPScript is not required. Follow [Installation](/installation) for PyKeePass.

For more file-layout details, see the [repository's KeePass notes](https://github.com/cngjsskaisme/nougat-worker/blob/feat/keepass-for-agents/tools/keepass/README.md).
