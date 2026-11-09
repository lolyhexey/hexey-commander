# Hexey Commander

Let ChatGPT and Claude work on your computer: run commands, read and edit files,
search code, and analyze binaries with Ghidra. Your computer connects out to
[commander.hexey.net](https://commander.hexey.net); the AI talks to that server
over MCP, and the server passes each call to your computer.

> **Beta.** Free to use. Everything the AI does runs with your user account on
> your computer, so only connect AI chats you trust and watch the live activity
> page at commander.hexey.net/dashboard/live.

## Start

Requires Node.js 22.12 or newer.

```bash
npx github:lolyhexey/hexey-commander remote
```

The first run opens your browser to sign in with Google and pair this computer.
Keep the command running while you use it. Stop with Ctrl+C.

```bash
npx github:lolyhexey/hexey-commander remote --logout   # unpair this computer
npx github:lolyhexey/hexey-commander remote --help
```

## Connect the AI

Add a custom connector (MCP server) with this URL and sign in with the same Google account:

```
https://commander.hexey.net/mcp
```

- **ChatGPT:** Settings → Connectors → Create (developer mode)
- **Claude:** Settings → Connectors → Add custom connector

## Ghidra (optional)

To give the AI Ghidra tools (decompile, disassemble, xrefs, call graphs, strings,
renames with undo, patching inside the Ghidra project, reports), install
[Ghidra](https://ghidra-sre.org) and a JDK it supports, then start with
`GHIDRA_INSTALL_DIR` set:

```powershell
$env:GHIDRA_INSTALL_DIR = "D:\ghidra_12.2_PUBLIC"
npx github:lolyhexey/hexey-commander remote
```

Java is found from `GHIDRA_JAVA_HOME`, `JAVA_HOME`, a JDK under
`C:\Program Files\Eclipse Adoptium` (and similar), or `java` on PATH. Analysis
results are kept in `%LOCALAPPDATA%\DesktopCommander\ghidra-projects`
(`GHIDRA_PROJECTS_DIR` to change). The binaries you analyze are never modified.

To give the AI jadx tools (decompile an APK, DEX, AAR or JAR to Java, list and
read classes, search the code, read the manifest and resources), download
[jadx](https://github.com/skylot/jadx/releases) (`jadx-<version>.zip`), unzip it
and start with `JADX_HOME` set to that folder:

```powershell
$env:JADX_HOME = "D:\jadx-1.5.6"
npx github:lolyhexey/hexey-commander remote
```

Java is found the same way as for Ghidra (`JADX_JAVA_HOME` first). Results are
kept in `%LOCALAPPDATA%\DesktopCommander\jadx-output` (`JADX_OUTPUT_DIR` to change).

## Settings

| Variable | Default | |
|---|---|---|
| `MCP_SERVER_URL` | `https://commander.hexey.net` | The server to connect to |
| `GHIDRA_INSTALL_DIR` | not set | Turns on the Ghidra tools |
| `GHIDRA_PROJECTS_DIR` | see above | Where Ghidra results are stored |
| `JADX_HOME` | not set | Turns on the jadx tools |
| `JADX_OUTPUT_DIR` | see above | Where jadx results are stored |

## ภาษาไทย

รัน `npx github:lolyhexey/hexey-commander remote` แล้วล็อกอินด้วย Google ในเบราว์เซอร์ที่เปิดขึ้นมา
จากนั้นเพิ่ม connector `https://commander.hexey.net/mcp` ใน ChatGPT หรือ Claude
ดูคำสั่งที่ AI สั่งได้ตลอดที่ commander.hexey.net/dashboard/live

## Credits and license

Based on [Desktop Commander MCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)
by Eduards Ruzga and contributors; its README is kept in
`docs/DESKTOP_COMMANDER_README.md`. MIT license, see `LICENSE`.
