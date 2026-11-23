# Cell Broadband Engine SPU Suite for IDA Pro 9.5 (`spu` + `spuemu` / `spudbg`)

A native C++17 reverse-engineering, emulation, and debugging suite for the **Cell Broadband Engine Synergistic Processor Unit (SPU ISA v1.2, SPU ABI v1.9, PS3 Isolation SPU)** targeting **IDA Pro 9.5**:

1. **`module/spu`** — Drop-in C++17 `spu.dll` processor module (deployed to `%APPDATA%\Hex-Rays\IDA Pro\procs\spu.dll` alongside `spu.py` shadow stub, `cfg/SPU.cfg`, and `til/spu_cbea.til`) replacing IDA's bundled Python `spu.py`.
2. **`plugins/spuemu`** ([`plugins/spuemu/README.md`](plugins/spuemu/README.md)) — Full 199-instruction SPU ISA v1.2 emulator (`spuemu_core.lib`, `spuemu.exe`, `spuemu_tests.exe`), GDB RSP server, pluggable & interactive **Channel Device Emulation Framework**, and native in-process IDA Pro 9.5 debugger plugin (`spudbg.dll`).
3. **`tests/run_comprehensive_validation.py`** — End-to-end synthetic 199-instruction sweep plus headless real-world validation on `lv0ldr` and `metldr` databases (including `spudec` decompiler integration).

---

## Processor Module Highlights (`spu.dll`)

- **Complete 199-instruction SPU ISA v1.2 decoder**:
  - Fixes `shlhi` (`0x07F`) from `RR` to `RI7` signed shift immediate.
  - Fixes `hbra`/`hbrr` 9-bit signed `ROH||ROL` and wraps targets with `& LSLR` (eliminating `0xFFFE...` `PR_NONAME` issues).
  - Supports `hbrp` (`P=1`), `syncc` (`C=1`), `D`/`E` interrupt branch suffixes (`bid`, `bie`, `bisld`, `bisle`, `iretd`, `irete`), and rejects illegal `D=E=1` encodings.
  - Validates `stop` reserved bits `[11:17] == 0` (preventing inline jump table entries from decoding as bogus `stop` instructions), marks `stopd` with `CF_STOP`, and validates `cflts`/`cfltu`/`csflt`/`cuflt` scale range `[0..127]`.
  - Omits architectural false-target `RT` on `heq`/`heqi`/`hgt`/`hgti`/`hlgt`/`hlgti`/`fscrwr` (and `nop` when `RT=0`), masks `*bi` immediates to 8 bits, quadword-aligns `lqa`/`stqa`/`lqr`/`stqr` targets (`& ~0xF`), and sets element dtypes (`dt_byte`..`dt_qword`) on `cbd`/`chd`/`cwd`/`cdd`.
- **Symbolic CBEA & PS3 Isolation Channel Names + Numeric Auto-Comments**:
  - Displays symbolic names (`MFC_Cmd`, `SPU_RdInMbox`, `SPU_IsoStat`, ...) by default while always annotating the original numeric channel ID in the auto-comment (e.g., `wrch MFC_Cmd, r9 ; Write Channel [ch21] (MFC GET, 0x40)`).
  - Decodes `dftsv` 7-bit IEEE special-value masks (`NaN|+Inf|-Inf|+0|-0|+Denorm|-Denorm`) and `ilhu`+`iohl` 32-bit pairs.
  - Processor options dialog (`Options -> General -> Analysis -> Processor specific analysis options`) toggles symbolic channels, GNU `$N`/`$chN` syntax, false-target comments, and `LSLR` mask.
- **Control Flow, Switch Tables & Stack Analysis**:
  - Accurate `dr_R`/`dr_W` data xrefs (`stqa`/`stqr` fixed to `dr_W`), `bisl`/`bisled` marked as calls, `func_does_return()` non-returning call support.
  - Automatic GCC/SN Systems SPU quadword-rotated jump table recovery (`ila` + `shli 2` + `clgti` + `lqx` + `rotqby` + `brnz` + `bi`), both absolute and relative, with automatic `lowcase` bias detection.
  - Full SPU ABI v1.9 stack tracking: back-chain `lqd sp, 0(sp)` restoration, `r127` frame pointer (`FUNC_FRAME`), large-frame `a sp, sp, rN` tracking, and 4-byte-only `nop`/`lnop` alignment detection.
- **SPU ABI v1.9, TIL & Merge**:
  - Built-in `COMP_GNU` SPU ABI (`r3..r74` 16-byte register slots, `sp+0x20` stack spill), precompiled `spu_cbea.til` (`vector` typedefs, `mfc_list_element_t`, channel enums), automatic legacy IDB upgrade, and IDA 9.5 `DEFINE_SIMPLE_PROCMOD_HANDLER`.

---

## Building & Deploying

### Integrated inside `ida-sdk` (`Ninja`)
```powershell
cmake -B src/build -S src -G Ninja
cmake --build src/build --target spu spuemu spuemu_tests spudbg
```

### Standalone Build
```powershell
cmake -S . -B build -G Ninja -DIDASDK=C:/path/to/ida-sdk/src
cmake --build build
ctest --test-dir build --output-on-failure
```

Post-build steps automatically deploy into `%APPDATA%\Hex-Rays\IDA Pro\`:
- `procs\spu.dll` and `procs\spu.py` (shadow stub hiding bundled `<IDA>\procs\spu.py`)
- `cfg\SPU.cfg`
- `til\spu\spu_cbea.til` (and `til\spu_cbea.til`)
- `plugins\spudbg.dll`

---

## Verification

```powershell
# 1. C++ emulator & pluggable channel device unit tests
src\build\module\spu\plugins\spuemu\spuemu_tests.exe

# 2. Processor module validation (synthetic 199-insn sweep + lv0ldr + metldr + spudec)
python tests/run_comprehensive_validation.py

# 3. Headless IDA Pro 9.5 native debugger validation (metldr + JSON/manual/Python channel devices)
python plugins/spuemu/tests/ida_headless_test.py
```
