# Cell SPU Emulator & Native IDA Pro 9.5 Debugger (`spuemu` / `spudbg.dll`)

Full 199-instruction **Cell Broadband Engine SPU ISA v1.2** emulator, standalone CLI/GDB RSP server (`spuemu.exe`), and native in-process **IDA Pro 9.5 debugger plugin** (`spudbg.dll`) with a **Pluggable & Interactive Channel Device Emulation Framework**.

---

## Features

- **Full 199-Instruction SPU ISA v1.2 Core**: 128 × 128-bit big-endian SIMD GPRs (`r0..r127`), 256 KiB Local Store with `LSLR` wrapping, 64-bit Main Memory (EA) address space, extended-range single-precision & IEEE-754 double-precision FP (`dftsv`, `fscrrd`/`fscrwr`), `shufb`/`selb`/`cb*..cd*`, `stop`/`stopd`/`heq*`/`hgt*`/`hlgt*`, and SPU interrupt delivery (`SRR0`, `IE`, vector `0x00000`, `iret`/`bid`/`bie`).
- **Built-in Architectural CBEA Hardware**:
  - **MFC DMA Engine** (`ch16..ch27`): synchronous `PUT`, `GET`, `PUTL`, `GETL`, `SNDSIG`, `GETLLAR`/`PUTLLC`/`PUTLLUC` (128-byte reservation), tag masks & status.
  - **Events & Decrementer** (`ch0..ch15`): `SPU_RdEventStat`, `SPU_WrEventMask`, `SPU_WrEventAck`, `SPU_WrDec`/`SPU_RdDec`, `SPU_RdSigNotify1`/`2`, `SPU_RdMachStat`, `SPU_WrSRR0`/`SPU_RdSRR0`.
  - **Mailboxes** (`ch28..ch30`): `SPU_WrOutMbox`, `SPU_RdInMbox`, `SPU_WrOutIntrMbox`.
  - **PS3 Isolation Channels** (`ch64..ch68`): `SPU_IsoCntl`, `SPU_IsoStat`, `SPU_IsoRootKey`, `SPU_IsoKey`, `SPU_IsoIdent`.
- **Native IDA Pro 9.5 Integration (`spudbg.dll`)**:
  - Auto-selects on `PLFM_SPU` databases.
  - Register views for **General registers** (`PC`, `sp`, `lr`, `SRR0`, `LSLR`, `IE`, `r2..r31`, `CYCLES`), **Vector registers (128-bit)** (`v0..v127`), **Floating-Point (`FPSCR`)**, and **MFC & Channels**.
  - Non-intrusive virtual breakpoints, Local Store read/write watchpoints, F8 step-over on `brsl`/`brasl`/`bisl`.

---

## Supplying Emulated Channel Devices (3 Ways)

### 1. Declarative JSON Config File
Load via `--channels devices.json` (CLI), `spuemu> dev load devices.json` (IDA console), `spudbg_load_devices("devices.json")` (IDC/IDAPython), or **auto-loaded** automatically when `<idb_stem>.spudev.json` sits next to your `.i64`!

See [`examples/ps3_spu_devices.json`](examples/ps3_spu_devices.json) for a full example. Supported device types:
- **`fifo`**: Preloaded `rx` word queue + captured `tx` word queue, with configurable `on_empty` (`"zero"`, `"repeat_last"`, `"stall"`, `"break"`, `"prompt"`).
- **`register`**: Stateful 32-bit word register (`value`, `count`, `read_only`, `clear_on_read`).
- **`responder`**: Pattern-matching protocol emulator (`when_write` value or `"*"` wildcard -> pushes `reply` array onto `reply_channel` or the same channel, plus optional `raise_event` bitmask).
- **`stub`** / **`logger`**: Logs all `rdch`/`wrch`/`rchcnt` transactions and returns fixed `default_read` / `default_count`.
- **`mailbox`**, **`mfc`**, **`event`**: Built-in architectural devices (can be configured with `rx`, `on_empty`, `break_on_read`, `break_on_write`, `prompt_on_empty`).
- **`dma_regions`**: Pre-populate 64-bit Main Memory EA regions from inline `"hex"`, a binary `"file"`, or zero-filled `"size"`.

### 2. Manual & Interactive Control in the Debugger
- **Break-on-empty / Break-on-read / Break-on-write**: When `rdch` hits an empty channel configured with `on_empty: "break"`, `PC` stays parked on `rdch` and IDA breaks into the debugger so you can inspect registers, inject the next word with `ch push`, and press F9/F7 to continue.
- **Interactive Prompt Mode**: Run `ch prompt <ch> on` (or `"prompt_on_empty": true` in JSON) to pop up IDA's `ask_str` dialog whenever an empty channel is read in GUI mode.
- **IDA `spuemu>` Debugger Console Commands** (`ev_rexec`):
  - `ch list`, `ch info <ch>`, `ch log [N]`
  - `ch push <ch> <val> [val2 ...]` — push 32-bit word(s) into channel RX queue
  - `ch pop <ch>` — pop 32-bit word written by SPU from channel TX queue
  - `ch set <ch> <val>` / `ch count <ch> <N>`
  - `ch break <ch> rd|wr|both|none` / `ch prompt <ch> on|off`
  - `ch attach <ch> fifo|register|stub|responder [opts...]` / `ch detach <ch>`
  - `dev load <file.json>` / `dev save <file.json>` / `dev reset`
  - `mfc`, `mbox [in <val> | out]`, `dma list | map <ea> <size> [name] | read <ea> <len>`, `irq`, `dec`, `vec <rN> [w0 w1 w2 w3]`, `fpscr`, `status`, `disasm`

### 3. Live IDAPython / IDC Script Callbacks
Attach a Python or IDC function directly to any channel (`0..127`) using `spudbg_set_ch_callback`:

```python
import ida_expr

def my_crypto_ch(ch, op, val):
    if op == "W":
        print(f"SPU wrote 0x{val:08X} to ch{ch}")
        return 0
    if op == "C":
        return 1  # rchcnt returns 1
    return 0xCAFEBABE  # rdch returns 0xCAFEBABE (return < 0 to break debugger!)

# Prefix with "py:" for IDAPython, or pass a bare IDC function name:
ida_expr.eval_idc_expr(ida_expr.idc_value_t(), 0, 'spudbg_set_ch_callback("SPU_IsoStat", "py:my_crypto_ch")')
```

---

## IDC / IDAPython Helper Reference (`spudbg_*`)

| Function | Description |
|---|---|
| `spudbg_start()` / `spudbg_stop()` | Initialize/reset or stop emulator session |
| `spudbg_step(n)` / `spudbg_run_to(ea, max_steps)` | Step `n` instructions or run until `ea` / stop event |
| `spudbg_get_reg(name)` / `spudbg_set_reg(name, val)` | Read/write scalar register (`PC`, `sp`, `lr`, `r2..r31`, `SRR0`, `LSLR`, `IE`, `SPU_Dec`) |
| `spudbg_get_vec(regno)` / `spudbg_set_vec(regno, w0, w1, w2, w3)` | Read/write 128-bit vector register `0..127` |
| `spudbg_read_u32(ls_addr)` / `spudbg_write_u32(ls_addr, val)` | Read/write big-endian word in 256 KiB Local Store |
| `spudbg_map_ea(ea, size, name)` | Map a 64-bit Main Memory EA region for MFC DMA |
| `spudbg_load_devices(json_path)` / `spudbg_save_devices(json_path)` | Load or export JSON channel device & DMA configuration |
| `spudbg_ch_attach(ch, type, arg)` | Attach `fifo`, `register`, `stub`, or `responder` to channel |
| `spudbg_ch_push(ch, val)` / `spudbg_ch_pop(ch)` | Push input word or pop captured output word |
| `spudbg_ch_set(ch, val)` / `spudbg_ch_set_count(ch, cnt)` | Set register value or override `rchcnt` |
| `spudbg_ch_set_break(ch, mode)` | Set break mode (`rd`, `wr`, `both`, `none`) |
| `spudbg_set_ch_callback(ch, fn_spec)` | Bind `"py:<func>"` or `"<idc_func>"` to channel |
| `spudbg_add_bpt(ea)` / `spudbg_del_bpt(ea)` | Add/remove non-intrusive virtual breakpoint |
| `spudbg_exec(cmdline)` | Run any `spuemu>` CLI command and return output string |
