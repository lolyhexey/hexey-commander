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

`npx github:...` needs `git` on PATH (without it npm fails with `spawn git ENOENT`).
If a previous Desktop Commander install limited file access, `remote` lists the
allowed folders at startup; set `"allowedDirectories": []` in
`~/.claude-server-commander/config.json` to allow every path.

### Android (Termux)

Install Termux from F-Droid or GitHub (not the old Play Store build), then:

```bash
pkg install nodejs git ripgrep
npx github:lolyhexey/hexey-commander remote
```

Open the sign-in link it prints in the phone's browser. `ripgrep` is needed for
file search: the bundled ripgrep has no Android build.

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

To let the AI change an APK (apktool decode to smali and resources, edit files,
build, zipalign, sign with a local debug key, install with adb), download
[apktool](https://github.com/iBotPeaches/Apktool/releases) (`apktool_<version>.jar`)
and start with `APKTOOL_JAR` set to it:

```powershell
$env:APKTOOL_JAR = "D:\tools\apktool_3.0.3.jar"
npx github:lolyhexey/hexey-commander remote
```

Signing and aligning use `apksigner` and `zipalign` from the newest Android SDK
build-tools (`ANDROID_HOME`, `ANDROID_SDK_ROOT` or `%LOCALAPPDATA%\Android\Sdk`);
installing uses that SDK's `adb`. The debug key is created on first build. Work
is kept in `%LOCALAPPDATA%\DesktopCommander\apktool` (`APKTOOL_WORK_DIR` to
change). The original APK is never modified.

To give the AI Frida tools (attach to or spawn processes on this computer or a
USB Android/iOS device, hook functions, Java/ObjC hooks, memory scan and
read/write, registers, JNI trace), install Python and the `frida` module, then
start with `FRIDA_ENABLED=1`:

```powershell
pip install frida
$env:FRIDA_ENABLED = "1"
npx github:lolyhexey/hexey-commander remote
```

For a phone, run a `frida-server` of the same version as the `frida` module on
it. `FRIDA_PYTHON` picks the Python to use (default `python`, then `py`).

To give the AI adb tools (list devices, shell commands, install, pull and push
files, logcat, pull an installed app's APKs for jadx or apktool), start with
`ADB_ENABLED=1`. adb comes from the Android SDK (`ANDROID_HOME`,
`ANDROID_SDK_ROOT`, `%LOCALAPPDATA%\Android\Sdk`), `ADB_PATH`, or PATH.

```powershell
$env:ADB_ENABLED = "1"
npx github:lolyhexey/hexey-commander remote
```

### What these tools can reach

The Ghidra, jadx, apktool, Frida and adb tools take any path on this computer
you name; `allowedDirectories` limits only the built-in file tools. Turning one
on lets the AI read the files it is pointed at, run code on attached devices
(adb, Frida) and install apps on them. Turn on only the ones you need.

## Settings

| Variable | Default | |
|---|---|---|
| `MCP_SERVER_URL` | `https://commander.hexey.net` | The server to connect to |
| `GHIDRA_INSTALL_DIR` | not set | Turns on the Ghidra tools |
| `GHIDRA_PROJECTS_DIR` | see above | Where Ghidra results are stored |
| `JADX_HOME` | not set | Turns on the jadx tools |
| `JADX_OUTPUT_DIR` | see above | Where jadx results are stored |
| `APKTOOL_JAR` | not set | Turns on the apktool tools |
| `APKTOOL_WORK_DIR` | see above | Where decoded and rebuilt APKs are kept |
| `ADB_ENABLED` | not set | `1` turns on the adb tools |
| `ADB_PATH` | from the SDK | adb to use |
| `ANDROID_HOME` | `%LOCALAPPDATA%\Android\Sdk` | Android SDK for apksigner, zipalign and adb |
| `FRIDA_ENABLED` | not set | `1` turns on the Frida tools |
| `FRIDA_PYTHON` | `python` | Python that has the `frida` module |
| `GHIDRA_JAVA_HOME` / `JADX_JAVA_HOME` / `APKTOOL_JAVA_HOME` / `JAVA_HOME` | auto | The JDK Ghidra / jadx / apktool run on |

## ภาษาไทย

รัน `npx github:lolyhexey/hexey-commander remote` แล้วล็อกอินด้วย Google ในเบราว์เซอร์ที่เปิดขึ้นมา
จากนั้นเพิ่ม connector `https://commander.hexey.net/mcp` ใน ChatGPT หรือ Claude
ดูคำสั่งที่ AI สั่งได้ตลอดที่ commander.hexey.net/dashboard/live

ต้องมี `git` ในเครื่องด้วย ถ้าไม่มีจะขึ้น `spawn git ENOENT`

ใช้บนมือถือ (Termux): `pkg install nodejs git ripgrep` แล้วรันคำสั่งเดียวกัน เปิดลิงก์ล็อกอินที่ขึ้นมาในเบราว์เซอร์ของมือถือ

ถ้าเข้าบางโฟลเดอร์ไม่ได้ (`Path not allowed`) แปลว่า config เก่าจำกัดโฟลเดอร์ไว้ ตอนเริ่ม `remote` จะแสดงรายการโฟลเดอร์นั้นให้เห็น แก้ `"allowedDirectories": []` ใน `~/.claude-server-commander/config.json` แล้วรันใหม่

เครื่องมือเสริม จะเปิดเมื่อตั้งค่า ENV ก่อนรัน `remote` (PowerShell):

- Ghidra: `$env:GHIDRA_INSTALL_DIR = "D:\ghidra_12.2_PUBLIC"` (ต้องมี JDK)
- jadx: `$env:JADX_HOME = "D:\jadx-1.5.6"` (โฟลเดอร์ที่แตกจาก `jadx-<version>.zip`, ต้องมี JDK)
- apktool: `$env:APKTOOL_JAR = "D:\tools\apktool_3.0.3.jar"` (แก้ smali แล้ว build, sign, install ได้; ต้องมี JDK และ Android SDK build-tools สำหรับ sign)
- adb: `$env:ADB_ENABLED = "1"` (สั่ง shell, ติดตั้งแอป, ดึงไฟล์และ APK, อ่าน logcat ของมือถือที่ต่ออยู่)
- Frida: `pip install frida` แล้ว `$env:FRIDA_ENABLED = "1"` (มือถือต้องรัน `frida-server` เวอร์ชันเดียวกัน)

ข้อควรรู้: เครื่องมือเหล่านี้เข้าถึงไฟล์ได้ทุก path โดยไม่สน `allowedDirectories` และ adb กับ Frida สั่งงานมือถือได้จริง เปิดเฉพาะตัวที่ใช้

ถ้าอยากให้ค่าอยู่ถาวร ใช้ `setx JADX_HOME "D:\jadx-1.5.6"` แล้วเปิดหน้าต่างใหม่

## Credits and license

Based on [Desktop Commander MCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)
by Eduards Ruzga and contributors; its README is kept in
`docs/DESKTOP_COMMANDER_README.md`. MIT license, see `LICENSE`.
