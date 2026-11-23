"""Headless IDA Pro 9.5 end-to-end test for spudbg.dll (Cell SPU emulator debugger).

Usage:
  1. Standalone driver (copies metldr.356.sym.elf.i64 to a temp scratch directory):
       python plugins/spuemu/tests/ida_headless_test.py
  2. Direct IDA script mode:
       idat.exe -A -S"plugins/spuemu/tests/ida_headless_test.py" <scratch_copy.i64>
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback


# Global Python callback invoked dynamically by spudbg_set_ch_callback("75", "py:spu_test_ch_cb")
_PY_CB_STATE = {"last_wr": 0, "calls": []}


def spu_test_ch_cb(ch, op, val):
    _PY_CB_STATE["calls"].append((ch, op, val))
    if op == "W":
        _PY_CB_STATE["last_wr"] = val
        return 0
    if op == "C":
        return 1
    return (_PY_CB_STATE["last_wr"] ^ 0xA5A5A5A5) & 0xFFFFFFFF


def run_inside_ida():
    import ida_auto
    import ida_bytes
    import ida_dbg
    import ida_expr
    import ida_ida
    import ida_idaapi
    import ida_idp
    import ida_lines
    import ida_loader
    import ida_ua
    import idc

    ida_auto.auto_wait()

    # Expose Python callback in __main__ / globals for extlang eval_expr
    import __main__
    __main__.spu_test_ch_cb = spu_test_ch_cb

    out_json = os.environ.get("SPUDBG_TEST_OUT", "")
    passed = []
    failures = []

    def check(cond, msg):
        if cond:
            passed.append(msg)
        else:
            failures.append(msg)

    def eval_idc(expr_str):
        rv = ida_expr.idc_value_t()
        err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, expr_str)
        if err:
            raise RuntimeError(f"eval_idc_expr({expr_str!r}) failed: {err}")
        if rv.vtype == ida_expr.VT_STR:
            return rv.c_str()
        if rv.vtype == ida_expr.VT_INT64:
            return int(rv.i64)
        return int(rv.num)

    def enc_rr(op11, rt, ra, rb):
        return ((op11 & 0x7FF) << 21) | ((rb & 0x7F) << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)

    def enc_ri16(op9, rt, i16):
        return ((op9 & 0x1FF) << 23) | ((i16 & 0xFFFF) << 7) | (rt & 0x7F)

    def enc_ri18(op7, rt, i18):
        return ((op7 & 0x7F) << 25) | ((i18 & 0x3FFFF) << 7) | (rt & 0x7F)

    try:
        # 1. Verify spu.dll + spudbg.dll loaded
        check(ida_idp.ph_get_id() == 59, f"Processor PLFM_SPU == 59 (got {ida_idp.ph_get_id()})")
        loaded = ida_dbg.load_debugger("spuemu", False) or ida_dbg.load_debugger("spudbg.dll", False)
        if not loaded:
            ida_loader.load_plugin("spudbg")
            loaded = ida_dbg.load_debugger("spuemu", False) or ida_dbg.load_debugger("spudbg.dll", False)
        check(bool(loaded), "Loaded spuemu debugger backend (spudbg.dll)")

        # 2. Start process via IDA debugger API
        started = ida_dbg.start_process("", "", "")
        check(started == 1, f"ida_dbg.start_process returned 1 (got {started})")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        check(ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP, "Process suspended at entry PC")

        pc0 = ida_dbg.get_reg_val("PC")
        sp0 = ida_dbg.get_reg_val("SP")
        lslr0 = ida_dbg.get_reg_val("LSLR")
        check(pc0 is not None and lslr0 == 0x3FFFF and sp0 == 0x3FFF0,
              f"Initial registers valid (PC=0x{pc0:X}, SP=0x{sp0:X}, LSLR=0x{lslr0:X})")

        # 3. Verify 128-bit vector register & MFC register access via IDA debugger
        v1 = ida_dbg.get_reg_val("v1")
        check(v1 is not None and len(v1) == 16 and v1[:4] == b"\x00\x03\xFF\xF0",
              f"128-bit vector register v1 (SP) big-endian bytes ok ({v1.hex() if isinstance(v1, (bytes, bytearray)) else v1})")
        check(ida_dbg.get_reg_val("MFC_LSA") == 0, "MFC_LSA channel register readable")

        # 4. Live Local Store matches IDB bytes
        idb_b = ida_bytes.get_bytes(pc0, 4)
        dbg_b = idc.get_bytes(pc0, 4, True)
        check(dbg_b == idb_b, f"Live LS memory at 0x{pc0:X} matches IDB")

        # 5. Single-step & verify PC advances
        check(bool(ida_dbg.step_into()), "ida_dbg.step_into() succeeded")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc1 = ida_dbg.get_reg_val("PC")
        check(pc1 != pc0, f"PC advanced after step_into (0x{pc0:X} -> 0x{pc1:X})")

        # 6. Step over first brsl encountered in startup
        found_call = False
        for _ in range(30):
            cur = ida_dbg.get_reg_val("PC")
            mn = (idc.print_insn_mnem(cur) or "").lower()
            if mn in ("brsl", "brasl", "bisl"):
                expected = cur + 4
                check(bool(ida_dbg.step_over()), f"step_over on {mn} @ 0x{cur:X}")
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
                after = ida_dbg.get_reg_val("PC")
                check(after == expected, f"step_over landed at 0x{after:X} (expected 0x{expected:X})")
                found_call = True
                break
            ida_dbg.step_into()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        check(found_call, "Exercised step_over on real metldr SPU call instruction")

        # 7. Test JSON channel devices, DMA region, manual ch push, break-on-empty, and Python callback!
        cfg = {
            "dma_regions": [
                {"name": "test_ea", "ea": "0x50000000", "hex": "DEADBEEFCAFEBABE0102030405060708"}
            ],
            "devices": [
                {"channel": "SPU_RdInMbox", "type": "fifo", "name": "mbox_fifo",
                 "rx": ["0x11223344"], "on_empty": "break"},
                {"channel": "SPU_IsoCntl", "type": "responder", "name": "iso_resp",
                 "rules": [{"when_write": "0x7", "reply": ["0x77778888"], "reply_channel": "SPU_IsoStat"}]},
                {"channel": "SPU_IsoStat", "type": "fifo", "name": "iso_stat", "on_empty": "break"},
            ]
        }
        tmp_cfg = os.path.join(tempfile.gettempdir(), "spudbg_test_devices.json")
        with open(tmp_cfg, "w") as f:
            json.dump(cfg, f)

        ok_ld = eval_idc(f'spudbg_load_devices("{tmp_cfg.replace(chr(92), "/")}")')
        check(ok_ld == 1, "spudbg_load_devices loaded JSON channel & DMA config")

        # Attach Python callback on channel 75!
        ok_cb = eval_idc('spudbg_set_ch_callback("75", "py:spu_test_ch_cb")')
        check(ok_cb == 1, "spudbg_set_ch_callback attached Python handler to ch75")

        # Write small SPU test program into scratch Local Store at 0x3E000:
        #   0x3E000: rdch r3, SPU_RdInMbox (29)   -> 0x11223344
        #   0x3E004: il r4, 7
        #   0x3E008: wrch SPU_IsoCntl (64), r4    -> responder pushes 0x77778888 into ch65
        #   0x3E00C: rdch r5, SPU_IsoStat (65)    -> 0x77778888
        #   0x3E010: il r6, 0x1234
        #   0x3E014: wrch ch75, r6                -> Python callback records 0x1234
        #   0x3E018: rdch r7, ch75                -> Python callback returns 0x1234 ^ 0xA5A5A5A5
        #   0x3E01C: ila r8, 0x3E200              -> MFC GET 16B from EA 0x50000000 -> LS 0x3E200
        #   0x3E020: wrch MFC_LSA (16), r8
        #   0x3E024: il r9, 0
        #   0x3E028: wrch MFC_EAH (17), r9
        #   0x3E02C: ilhu r10, 0x5000
        #   0x3E030: wrch MFC_EAL (18), r10
        #   0x3E034: il r11, 16
        #   0x3E038: wrch MFC_Size (19), r11
        #   0x3E03C: il r12, 0x40 (MFC GET)
        #   0x3E040: wrch MFC_Cmd (21), r12
        #   0x3E044: rdch r13, SPU_IsoStat (65)   -> empty FIFO -> ChannelBreak!
        #   0x3E048: stop 0x100
        prog = [
            enc_rr(0x00D, 3, 29, 0),
            enc_ri16(0x081, 4, 7),
            enc_rr(0x10D, 4, 64, 0),
            enc_rr(0x00D, 5, 65, 0),
            enc_ri16(0x081, 6, 0x1234),
            enc_rr(0x10D, 6, 75, 0),
            enc_rr(0x00D, 7, 75, 0),
            enc_ri18(0x21, 8, 0x3E200),
            enc_rr(0x10D, 8, 16, 0),
            enc_ri16(0x081, 9, 0),
            enc_rr(0x10D, 9, 17, 0),
            enc_ri16(0x082, 10, 0x5000),
            enc_rr(0x10D, 10, 18, 0),
            enc_ri16(0x081, 11, 16),
            enc_rr(0x10D, 11, 19, 0),
            enc_ri16(0x081, 12, 0x40),
            enc_rr(0x10D, 12, 21, 0),
            enc_rr(0x00D, 13, 65, 0),
            enc_rr(0x000, 0, 0, 0) | 0x100,
        ]
        for idx, w in enumerate(prog):
            eval_idc(f"spudbg_write_u32(0x{0x3E000 + idx * 4:X}, 0x{w:08X})")

        eval_idc('spudbg_set_reg("PC", 0x3E000)')
        # Run until empty channel break at 0x3E044
        eval_idc("spudbg_run_to(0x3E048, 100)")

        r3 = eval_idc('spudbg_get_reg("r3")') & 0xFFFFFFFF
        r5 = eval_idc('spudbg_get_reg("r5")') & 0xFFFFFFFF
        r7 = eval_idc('spudbg_get_reg("r7")') & 0xFFFFFFFF
        pc_brk = eval_idc('spudbg_get_reg("PC")') & 0xFFFFFFFF
        dma_w0 = eval_idc("spudbg_read_u32(0x3E200)") & 0xFFFFFFFF
        dma_w1 = eval_idc("spudbg_read_u32(0x3E204)") & 0xFFFFFFFF

        check(r3 == 0x11223344, f"JSON FIFO SPU_RdInMbox delivered 0x{r3:08X}")
        check(r5 == 0x77778888, f"JSON Responder SPU_IsoCntl->SPU_IsoStat delivered 0x{r5:08X}")
        check(r7 == (0x1234 ^ 0xA5A5A5A5), f"IDAPython channel callback ch75 returned 0x{r7:08X}")
        check(len(_PY_CB_STATE["calls"]) == 2, f"IDAPython callback invoked for W & R ({_PY_CB_STATE['calls']})")
        check(dma_w0 == 0xDEADBEEF and dma_w1 == 0xCAFEBABE,
              f"MFC GET copied JSON EA region -> LS (0x{dma_w0:08X} 0x{dma_w1:08X})")
        check(pc_brk == 0x3E044, f"Empty ch65 parked PC at 0x{pc_brk:X} (expected 0x3E044)")

        # Manually supply channel word via spudbg_ch_push & step past rdch!
        eval_idc('spudbg_ch_push("SPU_IsoStat", 0x55667788)')
        pc_resumed = eval_idc("spudbg_step(1)") & 0xFFFFFFFF
        r13 = eval_idc('spudbg_get_reg("r13")') & 0xFFFFFFFF
        check(pc_resumed == 0x3E048 and r13 == 0x55667788,
              f"Manual spudbg_ch_push unblocked rdch -> r13=0x{r13:08X}, PC=0x{pc_resumed:X}")

        # Verify spudbg_exec CLI output
        status_out = eval_idc('spudbg_exec("status")')
        ch_list_out = eval_idc('spudbg_exec("ch list")')
        check("PC=0x3E048" in status_out and "iso_resp" in ch_list_out and "py:spu_test_ch_cb" in ch_list_out,
              "spuemu> CLI status and ch list report live device state")

        # Cleanly exit debugger
        ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 2)

        if os.path.exists(tmp_cfg):
            os.remove(tmp_cfg)

    except BaseException as exc:
        failures.append(f"Unhandled exception: {exc}\n{traceback.format_exc()}")

    result = {"passed": passed, "failures": failures}
    if out_json:
        with open(out_json, "w") as f:
            json.dump(result, f, indent=2)
    else:
        for p in passed:
            print("  [PASS]", p)
        for fl in failures:
            print("  [FAIL]", fl)
        print(f"Summary: {len(passed)} passed, {len(failures)} failed")

    idc.qexit(0 if not failures else 1)


def run_standalone():
    idat = r"C:\Program Files\IDA Professional 9.5\idat.exe"
    script_path = os.path.abspath(__file__)
    metldr_src = os.path.abspath(os.path.join(
        os.path.dirname(script_path), "..", "..", "..", "..", "..", "plugins", "spudec", "metldr.356.sym.elf.i64"
    ))
    if not os.path.exists(metldr_src):
        raise FileNotFoundError(f"metldr test IDB not found at {metldr_src}")

    with tempfile.TemporaryDirectory(prefix="spudbg_test_") as tmp:
        ml_copy = os.path.join(tmp, "metldr_dbg_copy.i64")
        out_json = os.path.join(tmp, "out.json")
        log_path = os.path.join(tmp, "idat.log")
        shutil.copy2(metldr_src, ml_copy)

        env = os.environ.copy()
        env["SPUDBG_TEST_OUT"] = out_json

        print("=== Headless IDA Pro 9.5 spudbg.dll End-to-End Test (metldr scratch copy) ===", flush=True)
        subprocess.run([idat, "-A", f"-L{log_path}", f"-S{script_path}", ml_copy],
                       env=env, check=False, timeout=60)
        if not os.path.exists(out_json):
            if os.path.exists(log_path):
                print(open(log_path, "r", errors="replace").read()[-2000:], flush=True)
            raise RuntimeError("spudbg headless test did not produce output JSON")

        with open(out_json, "r") as f:
            res = json.load(f)
        for p in res["passed"]:
            print("  [PASS]", p, flush=True)
        for fl in res["failures"]:
            print("  [FAIL]", fl, flush=True)
        print(f"\nTOTAL: {len(res['passed'])} passed, {len(res['failures'])} failed", flush=True)
        sys.exit(0 if not res["failures"] else 1)


if __name__ == "__main__":
    try:
        import ida_idp  # noqa: F401
        in_ida = True
    except ImportError:
        in_ida = False

    if in_ida:
        import idc
        try:
            run_inside_ida()
        except BaseException:
            traceback.print_exc()
            idc.qexit(2)
    else:
        run_standalone()
