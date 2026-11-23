"""Comprehensive validation suite for the C++17 Cell SPU IDA Pro 9.5 processor module.

Usage:
  1. Standalone driver (runs synthetic 199-instruction binary + lv0ldr + metldr scratch tests):
       python tests/run_comprehensive_validation.py [--idat <path/to/idat.exe>]
  2. Direct IDA script mode (invoked automatically by standalone driver, or manually):
       idat.exe -A -S"tests/run_comprehensive_validation.py" <scratch_copy.i64>
"""

import os
import sys
import json
import struct
import shutil
import tempfile
import subprocess


# ---------------------------------------------------------------------------
# SPU ISA v1.2 big-endian instruction encoders for synthetic test generation
# ---------------------------------------------------------------------------
def enc_rrr(op4, rt, ra, rb, rc):
    return ((op4 & 0xF) << 28) | ((rt & 0x7F) << 21) | ((rb & 0x7F) << 14) | ((ra & 0x7F) << 7) | (rc & 0x7F)

def enc_rr(op11, rt, ra, rb):
    return ((op11 & 0x7FF) << 21) | ((rb & 0x7F) << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)

def enc_ri7(op11, rt, ra, i7):
    return ((op11 & 0x7FF) << 21) | ((i7 & 0x7F) << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)

def enc_ri8(op10, rt, ra, i8):
    return ((op10 & 0x3FF) << 22) | ((i8 & 0xFF) << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)

def enc_ri10(op8, rt, ra, i10):
    return ((op8 & 0xFF) << 24) | ((i10 & 0x3FF) << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)

def enc_ri16(op9, rt, i16):
    return ((op9 & 0x1FF) << 23) | ((i16 & 0xFFFF) << 7) | (rt & 0x7F)

def enc_ri18(op7, rt, i18):
    return ((op7 & 0x7F) << 25) | ((i18 & 0x3FFFF) << 7) | (rt & 0x7F)

def enc_hbr_ar(op7, ro9, i16):
    roh = (ro9 >> 7) & 0x3
    rol = ro9 & 0x7F
    return ((op7 & 0x7F) << 25) | (roh << 23) | ((i16 & 0xFFFF) << 7) | rol

def enc_hbr(p, ro9, ra):
    roh = (ro9 >> 7) & 0x3
    rol = ro9 & 0x7F
    rb = ((1 if p else 0) << 6) | roh
    return (0x1AC << 21) | (rb << 14) | ((ra & 0x7F) << 7) | rol

def enc_br_ind(op11, rt, ra, d=0, e=0):
    rb = ((d & 1) << 5) | ((e & 1) << 4)
    return ((op11 & 0x7FF) << 21) | (rb << 14) | ((ra & 0x7F) << 7) | (rt & 0x7F)


def build_synthetic_binary():
    """Return (bytes, test_map) for all 199 ISA instructions + edge cases."""
    words = []
    markers = {}

    def emit(word, tag=None):
        ea = len(words) * 4
        if tag is not None:
            markers[tag] = ea
        words.append(word & 0xFFFFFFFF)
        return ea

    # --- Block 1: Edge-case instruction tests ---
    emit(enc_ri7(0x07F, 3, 4, 7), "shlhi_pos")            # shlhi r3, r4, 7
    emit(enc_ri7(0x07F, 5, 6, (-3) & 0x7F), "shlhi_neg")  # shlhi r5, r6, -3
    emit(enc_hbr_ar(0x008, (-4) & 0x1FF, 0x100 >> 2), "hbra_neg_ro")   # hbra with negative 9-bit RO -> wrap
    emit(enc_hbr_ar(0x009, 2, (-8) & 0xFFFF), "hbrr_neg_targ")         # hbrr with negative i16 -> LSLR wrap
    emit(enc_hbr(1, 0, 0), "hbrp")                        # hbrp (P=1)
    emit(enc_hbr(0, 4, 5), "hbr")                         # hbr loc, r5
    emit(enc_ri10(0x016, 3, 4, 0x3A5), "andbi_8bit")      # andbi: only low 8 bits (0xA5)
    emit(enc_ri10(0x04E, 3, 4, 0x3FF), "cgtbi_s8")        # cgtbi: signed 8-bit (-1)
    emit(enc_ri10(0x07F, 0, 5, 0x12), "heqi_2op")         # heqi r5, 0x12 (NO false target lr)
    emit(enc_rr(0x3D8, 0, 5, 6), "heq_2op")               # heq r5, r6 (NO false target lr)
    emit(enc_rr(0x258, 0, 5, 6), "hgt_2op")               # hgt r5, r6
    emit(enc_rr(0x2D8, 0, 5, 6), "hlgt_2op")              # hlgt r5, r6
    emit(enc_rr(0x3BA, 0, 7, 0), "fscrwr_1op")            # fscrwr r7 (NO false target)
    emit(enc_rr(0x201, 0, 0, 0), "nop_0op")               # nop (RT=0 omitted)
    emit(enc_rr(0x201, 127, 0, 0), "nop_r127")            # nop r127
    emit(enc_rr(0x001, 0, 0, 0), "lnop")                  # lnop
    emit(enc_rr(0x002, 0, 0, 0), "sync")                  # sync
    emit((0x002 << 21) | (1 << 20), "syncc")              # syncc (C=1)
    emit(enc_rr(0x000, 0, 0, 0) | 0x2104, "stop_valid")   # stop 0x2104
    emit(0x000193D0, "stop_invalid_reserved")             # bits[11:17] != 0 -> MUST NOT decode!
    emit(enc_rr(0x140, 3, 4, 5), "stopd")                 # stopd (CF_STOP)
    emit(enc_br_ind(0x1A8, 0, 0, d=1, e=0), "bid_lr")     # bid lr
    emit(enc_br_ind(0x1A8, 0, 0, d=0, e=1), "bie_lr")     # bie lr
    emit(enc_br_ind(0x1A8, 0, 3, d=1, e=1), "bi_de_inv")  # D=1,E=1 -> MUST NOT decode!
    emit(enc_br_ind(0x1A9, 0, 5, d=1, e=0), "bisld")      # bisld lr, r5
    emit(enc_br_ind(0x1AA, 0, 0, d=0, e=1), "irete")      # irete
    emit(enc_ri8(0x1D8, 3, 4, 173 - 32), "cflts_ok")      # cflts r3, r4, 32
    emit(enc_ri8(0x1D8, 3, 4, 174), "cflts_inv")          # scale = -1 -> MUST NOT decode!
    emit(enc_ri8(0x1DA, 3, 4, 155 - 16), "csflt_ok")      # csflt r3, r4, 16
    emit(enc_ri8(0x1DA, 3, 4, 10), "csflt_inv")           # scale = 145 > 127 -> MUST NOT decode!
    emit(enc_ri16(0x041, 3, (0x1004 >> 2)), "stqa_align") # stqa r3, 0x1000 (masked & ~0xF, dr_W)
    emit(enc_ri16(0x061, 4, (0x1008 >> 2)), "lqa_align")  # lqa r4, 0x1000 (masked & ~0xF, dr_R)
    emit(enc_ri7(0x1F4, 3, 4, 2), "cbd_dt")               # cbd -> dt_byte
    emit(enc_ri7(0x1F5, 3, 4, 2), "chd_dt")               # chd -> dt_word
    emit(enc_ri7(0x1F6, 3, 4, 4), "cwd_dt")               # cwd -> dt_dword
    emit(enc_ri7(0x1F7, 3, 4, 8), "cdd_dt")               # cdd -> dt_qword

    # Channel symbolic names + MFC_Cmd decoding + PS3 Isolation channel
    emit(enc_ri16(0x081, 9, 0x0040), "il_mfc_get")        # il r9, 0x40 (MFC GET)
    emit(enc_rr(0x10D, 9, 21, 0), "wrch_mfc_cmd")         # wrch MFC_Cmd, r9 -> [ch21] (MFC GET)
    emit(enc_rr(0x00D, 8, 29, 0), "rdch_inmbox")          # rdch r8, SPU_RdInMbox -> [ch29]
    emit(enc_rr(0x00F, 8, 65, 0), "rchcnt_ps3_iso")       # rchcnt r8, PS3_ISO_65 -> [ch65]

    # dftsv bitmask auto-comment
    emit(enc_ri7(0x3BF, 3, 4, 0x62), "dftsv_mask")        # 0x40|0x20|0x02 = NaN|+Inf|-0

    # ilhu + iohl pair fusing
    emit(enc_ri16(0x082, 12, 0x0000), "ilhu_pair")
    emit(enc_ri16(0x0C1, 12, 0x1000), "iohl_pair")        # -> 0x00001000

    # Align sequence (4 x nop/lnop = 16 bytes)
    emit(enc_rr(0x201, 0, 0, 0), "align_seq")
    emit(enc_rr(0x001, 0, 0, 0))
    emit(enc_rr(0x201, 0, 0, 0))
    emit(enc_rr(0x001, 0, 0, 0))

    # --- Block 2: All 199 ISA instructions sweep ---
    # 4-bit (6)
    all199 = []
    for op, name in [(0x8,"selb"),(0xB,"shufb"),(0xC,"mpya"),(0xD,"fnms"),(0xE,"fma"),(0xF,"fms")]:
        all199.append((name, enc_rrr(op, 3, 4, 5, 6)))
    # 7-bit (3)
    all199.append(("hbra", enc_hbr_ar(0x08, 4, 0x10)))
    all199.append(("hbrr", enc_hbr_ar(0x09, 4, 0x10)))
    all199.append(("ila",  enc_ri18(0x21, 3, 0x100)))
    # 8-bit (29)
    for op, name in [
        (0x04,"ori"),(0x05,"orhi"),(0x06,"orbi"),(0x0C,"sfi"),(0x0D,"sfhi"),
        (0x14,"andi"),(0x15,"andhi"),(0x16,"andbi"),(0x1C,"ai"),(0x1D,"ahi"),
        (0x24,"stqd"),(0x34,"lqd"),(0x44,"xori"),(0x45,"xorhi"),(0x46,"xorbi"),
        (0x4C,"cgti"),(0x4D,"cgthi"),(0x4E,"cgtbi"),(0x4F,"hgti"),(0x5C,"clgti"),
        (0x5D,"clgthi"),(0x5E,"clgtbi"),(0x5F,"hlgti"),(0x74,"mpyi"),(0x75,"mpyui"),
        (0x7C,"ceqi"),(0x7D,"ceqhi"),(0x7E,"ceqbi"),(0x7F,"heqi"),
    ]:
        # Use imm=1 so ori doesn't become simplified `lr`
        all199.append((name, enc_ri10(op, 3, 4, 1)))
    # 9-bit (17)
    for op, name in [
        (0x040,"brz"),(0x041,"stqa"),(0x042,"brnz"),(0x044,"brhz"),(0x046,"brhnz"),
        (0x047,"stqr"),(0x060,"bra"),(0x061,"lqa"),(0x062,"brasl"),(0x064,"br"),
        (0x065,"fsmbi"),(0x066,"brsl"),(0x067,"lqr"),(0x081,"il"),(0x082,"ilhu"),
        (0x083,"ilh"),(0x0C1,"iohl"),
    ]:
        all199.append((name, enc_ri16(op, 3, 4)))
    # 10-bit (4)
    for op, name, i8 in [(0x1D8,"cflts",170),(0x1D9,"cfltu",170),(0x1DA,"csflt",150),(0x1DB,"cuflt",150)]:
        all199.append((name, enc_ri8(op, 3, 4, i8)))
    # 11-bit (140)
    ops_11 = [
        (0x000,"stop"),(0x001,"lnop"),(0x002,"sync"),(0x003,"dsync"),(0x00C,"mfspr"),
        (0x00D,"rdch"),(0x00F,"rchcnt"),(0x040,"sf"),(0x041,"or"),(0x042,"bg"),
        (0x048,"sfh"),(0x049,"nor"),(0x053,"absdb"),(0x058,"rot"),(0x059,"rotm"),
        (0x05A,"rotma"),(0x05B,"shl"),(0x05C,"roth"),(0x05D,"rothm"),(0x05E,"rotmah"),
        (0x05F,"shlh"),(0x078,"roti"),(0x079,"rotmi"),(0x07A,"rotmai"),(0x07B,"shli"),
        (0x07C,"rothi"),(0x07D,"rothmi"),(0x07E,"rotmahi"),(0x07F,"shlhi"),(0x0C0,"a"),
        (0x0C1,"and"),(0x0C2,"cg"),(0x0C8,"ah"),(0x0C9,"nand"),(0x0D3,"avgb"),
        (0x10C,"mtspr"),(0x10D,"wrch"),(0x128,"biz"),(0x129,"binz"),(0x12A,"bihz"),
        (0x12B,"bihnz"),(0x140,"stopd"),(0x144,"stqx"),(0x1A8,"bi"),(0x1A9,"bisl"),
        (0x1AA,"iret"),(0x1AB,"bisled"),(0x1AC,"hbr"),(0x1B0,"gb"),(0x1B1,"gbh"),
        (0x1B2,"gbb"),(0x1B4,"fsm"),(0x1B5,"fsmh"),(0x1B6,"fsmb"),(0x1B8,"frest"),
        (0x1B9,"frsqest"),(0x1C4,"lqx"),(0x1CC,"rotqbybi"),(0x1CD,"rotqmbybi"),(0x1CF,"shlqbybi"),
        (0x1D4,"cbx"),(0x1D5,"chx"),(0x1D6,"cwx"),(0x1D7,"cdx"),(0x1D8,"rotqbi"),
        (0x1D9,"rotqmbi"),(0x1DB,"shlqbi"),(0x1DC,"rotqby"),(0x1DD,"rotqmby"),(0x1DF,"shlqby"),
        (0x1F0,"orx"),(0x1F4,"cbd"),(0x1F5,"chd"),(0x1F6,"cwd"),(0x1F7,"cdd"),
        (0x1F8,"rotqbii"),(0x1F9,"rotqmbii"),(0x1FB,"shlqbii"),(0x1FC,"rotqbyi"),(0x1FD,"rotqmbyi"),
        (0x1FF,"shlqbyi"),(0x201,"nop"),(0x240,"cgt"),(0x241,"xor"),(0x248,"cgth"),
        (0x249,"eqv"),(0x250,"cgtb"),(0x253,"sumb"),(0x258,"hgt"),(0x2A5,"clz"),
        (0x2A6,"xswd"),(0x2AE,"xshw"),(0x2B4,"cntb"),(0x2B6,"xsbh"),(0x2C0,"clgt"),
        (0x2C1,"andc"),(0x2C2,"fcgt"),(0x2C3,"dfcgt"),(0x2C4,"fa"),(0x2C5,"fs"),
        (0x2C6,"fm"),(0x2C8,"clgth"),(0x2C9,"orc"),(0x2CA,"fcmgt"),(0x2CB,"dfcmgt"),
        (0x2CC,"dfa"),(0x2CD,"dfs"),(0x2CE,"dfm"),(0x2D0,"clgtb"),(0x2D8,"hlgt"),
        (0x340,"addx"),(0x341,"sfx"),(0x342,"cgx"),(0x343,"bgx"),(0x346,"mpyhha"),
        (0x34E,"mpyhhau"),(0x35C,"dfma"),(0x35D,"dfms"),(0x35E,"dfnms"),(0x35F,"dfnma"),
        (0x398,"fscrrd"),(0x3B8,"fesd"),(0x3B9,"frds"),(0x3BA,"fscrwr"),(0x3BF,"dftsv"),
        (0x3C0,"ceq"),(0x3C2,"fceq"),(0x3C3,"dfceq"),(0x3C4,"mpy"),(0x3C5,"mpyh"),
        (0x3C6,"mpyhh"),(0x3C7,"mpys"),(0x3C8,"ceqh"),(0x3CA,"fcmeq"),(0x3CB,"dfcmeq"),
        (0x3CC,"mpyu"),(0x3CE,"mpyhhu"),(0x3D0,"ceqb"),(0x3D4,"fi"),(0x3D8,"heq"),
    ]
    for op, name in ops_11:
        if name in ("stop", "lnop", "sync", "dsync"):
            w = enc_rr(op, 0, 0, 0)
        elif name in ("biz", "binz", "bihz", "bihnz", "bi", "bisl", "iret", "bisled"):
            w = enc_br_ind(op, 3, 4, d=0, e=0)
        elif name == "hbr":
            w = enc_hbr(0, 4, 5)
        elif name == "shlqbyi":
            w = enc_ri7(op, 3, 4, 1)  # i7=1 so it doesn't simplify to `lr`
        elif name == "rdch" or name == "rchcnt" or name == "wrch":
            w = enc_rr(op, 3, 21, 0)
        else:
            w = enc_rr(op, 3, 4, 5)
        all199.append((name, w))

    assert len(all199) == 199, f"Expected 199 instructions, got {len(all199)}"
    markers["all199_start"] = len(words) * 4
    markers["all199_names"] = [n for n, _ in all199]
    for _, w in all199:
        emit(w)

    # Pad to 0x1020 so 0x1000 data target is loaded inside the binary segment
    while len(words) * 4 < 0x1020:
        emit(0)

    raw = b"".join(struct.pack(">I", w) for w in words)
    return raw, markers


# ---------------------------------------------------------------------------
# In-IDA verification entry point
# ---------------------------------------------------------------------------
def run_inside_ida():
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_frame
    import ida_idp
    import ida_lines
    import ida_nalt
    import ida_segment
    import ida_typeinf
    import ida_ua
    import ida_xref
    import idautils
    import idc

    ida_auto.auto_wait()
    idc.set_inf_attr(idc.INF_CMTFLG, idc.get_inf_attr(idc.INF_CMTFLG) | idc.SCF_ALLCMT)

    mode = os.environ.get("SPU_VAL_MODE", "idb")
    out_json = os.environ.get("SPU_VAL_OUT", "")
    failures = []
    passed = []

    def check(cond, msg):
        if cond:
            passed.append(msg)
        else:
            failures.append(msg)

    # Common processor module sanity checks
    check(ida_idp.ph_get_id() == 59, f"PLFM_SPU == 59 (got {ida_idp.ph_get_id()})")
    icnt = ida_idp.ph_get_instruc_end() - ida_idp.ph_get_instruc_start()
    check(icnt == 201, f"Native spu.dll loaded with 201 itypes (got {icnt})")
    check((ida_idp.ph_get_flag() & ida_idp.PR_TYPEINFO) != 0, "PR_TYPEINFO set")
    check(idc.get_inf_attr(idc.INF_COMPILER) == ida_typeinf.COMP_GNU,
          f"COMP_GNU active (got {idc.get_inf_attr(idc.INF_COMPILER)})")

    if mode == "synthetic":
        with open(os.environ["SPU_VAL_MARKERS"], "r") as f:
            m = json.load(f)

        def dec(tag):
            ea = m[tag]
            ida_bytes.del_items(ea, 0, 4)
            sz = ida_ua.create_insn(ea)
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
            return sz, insn, line

        # 1. shlhi RI7
        sz, ins, line = dec("shlhi_pos")
        check(sz == 4 and ins.Op3.type == ida_ua.o_imm and ins.Op3.value == 7,
              f"shlhi_pos RI7: {line}")
        sz, ins, line = dec("shlhi_neg")
        check(sz == 4 and ins.Op3.type == ida_ua.o_imm and (ins.Op3.value & 0xFFFFFFFF) == 0xFFFFFFFD,
              f"shlhi_neg RI7 signed: {line}")

        # 2. hbra/hbrr 9-bit RO & LSLR wrap
        sz, ins, line = dec("hbra_neg_ro")
        check(sz == 4 and ins.Op1.addr <= 0x3FFFC and ins.Op2.addr == 0x100,
              f"hbra_neg_ro wrapped: {line} (op1=0x{ins.Op1.addr:X}, op2=0x{ins.Op2.addr:X})")
        sz, ins, line = dec("hbrr_neg_targ")
        check(sz == 4 and ins.Op2.addr <= 0x3FFFC and ins.Op2.addr >= 0x3FFC0,
              f"hbrr_neg_targ LSLR wrap: {line} (op2=0x{ins.Op2.addr:X})")

        # 3. hbr / hbrp
        sz, ins, line = dec("hbrp")
        check(sz == 4 and "hbrp" in line, f"hbrp prefetch: {line}")
        sz, ins, line = dec("hbr")
        check(sz == 4 and line.strip().startswith("hbr"), f"hbr r-form: {line}")

        # 4. 8-bit *bi
        sz, ins, line = dec("andbi_8bit")
        check(sz == 4 and ins.Op3.value == 0xA5, f"andbi 8-bit mask: {line} (val=0x{ins.Op3.value:X})")
        sz, ins, line = dec("cgtbi_s8")
        check(sz == 4 and (ins.Op3.value & 0xFFFFFFFF) == 0xFFFFFFFF, f"cgtbi signed 8-bit: {line}")

        # 5. False-target omission
        for tag in ("heqi_2op", "heq_2op", "hgt_2op", "hlgt_2op"):
            sz, ins, line = dec(tag)
            check(sz == 4 and ins.Op3.type == ida_ua.o_void and "lr" not in line.split(";")[0],
                  f"{tag} omits false target: {line}")
        sz, ins, line = dec("fscrwr_1op")
        check(sz == 4 and ins.Op2.type == ida_ua.o_void and "lr" not in line.split(";")[0],
              f"fscrwr_1op omits false target: {line}")
        sz, ins, line = dec("nop_0op")
        check(sz == 4 and ins.Op1.type == ida_ua.o_void, f"nop RT=0 omits op: {line}")
        sz, ins, line = dec("nop_r127")
        check(sz == 4 and ins.Op1.type == ida_ua.o_reg and ins.Op1.reg == 127, f"nop r127 keeps op: {line}")

        # 6. sync / syncc
        sz, ins, line = dec("sync")
        check(sz == 4 and line.strip().startswith("sync") and not line.strip().startswith("syncc"), f"sync: {line}")
        sz, ins, line = dec("syncc")
        check(sz == 4 and "syncc" in line, f"syncc (C=1): {line}")

        # 7. stop reserved bits & stopd CF_STOP
        sz, ins, line = dec("stop_valid")
        check(sz == 4 and ins.Op1.value == 0x2104, f"stop_valid: {line}")
        ea_inv = m["stop_invalid_reserved"]
        ida_bytes.del_items(ea_inv, 0, 4)
        ins_inv = ida_ua.insn_t()
        check(ida_ua.decode_insn(ins_inv, ea_inv) == 0,
              f"stop_invalid_reserved (0x000193D0) rejected by ana")
        sz, ins, line = dec("stopd")
        ida_auto.auto_wait()
        has_flow = any(xr.type == ida_xref.fl_F for xr in idautils.XrefsFrom(m["stopd"], 0))
        check(sz == 4 and not has_flow, f"stopd has CF_STOP (no fl_F): {line}")

        # 8. D/E suffixes & D=E=1 rejection
        for tag, exp in [("bid_lr", "bid"), ("bie_lr", "bie"), ("bisld", "bisld"), ("irete", "irete")]:
            sz, ins, line = dec(tag)
            check(sz == 4 and line.strip().startswith(exp), f"{tag} renders {exp}: {line}")
        ins_de = ida_ua.insn_t()
        check(ida_ua.decode_insn(ins_de, m["bi_de_inv"]) == 0, "bi D=1,E=1 rejected by ana")

        # 9. Float conversion scale validation
        sz, ins, line = dec("cflts_ok")
        check(sz == 4 and ins.Op3.value == 32, f"cflts valid scale=32: {line}")
        ins_fi = ida_ua.insn_t()
        check(ida_ua.decode_insn(ins_fi, m["cflts_inv"]) == 0, "cflts scale=-1 rejected")
        sz, ins, line = dec("csflt_ok")
        check(sz == 4 and ins.Op3.value == 16, f"csflt valid scale=16: {line}")
        check(ida_ua.decode_insn(ins_fi, m["csflt_inv"]) == 0, "csflt scale=145 rejected")

        # 10. stqa / lqa quadword alignment & dr_W/dr_R
        sz, ins, line = dec("stqa_align")
        ida_auto.auto_wait()
        xr_st = [xr.type for xr in idautils.XrefsFrom(m["stqa_align"], 0) if xr.to == 0x1000]
        check(sz == 4 and ins.Op2.addr == 0x1000 and ida_xref.dr_W in xr_st and ida_xref.dr_R not in xr_st,
              f"stqa masks & ~0xF and creates dr_W: {line} xrefs={xr_st}")
        sz, ins, line = dec("lqa_align")
        ida_auto.auto_wait()
        xr_ld = [xr.type for xr in idautils.XrefsFrom(m["lqa_align"], 0) if xr.to == 0x1000]
        check(sz == 4 and ins.Op2.addr == 0x1000 and ida_xref.dr_R in xr_ld,
              f"lqa masks & ~0xF and creates dr_R: {line} xrefs={xr_ld}")

        # 11. cbd/chd/cwd/cdd element dtypes
        for tag, exp_dt in [("cbd_dt", ida_ua.dt_byte), ("chd_dt", ida_ua.dt_word),
                            ("cwd_dt", ida_ua.dt_dword), ("cdd_dt", ida_ua.dt_qword)]:
            sz, ins, line = dec(tag)
            check(sz == 4 and ins.Op2.dtype == exp_dt, f"{tag} dtype={ins.Op2.dtype} (exp {exp_dt})")

        # 12. Symbolic channels + [chN] auto-comment + MFC_Cmd + PS3 Isolation
        dec("il_mfc_get")
        sz, ins, line = dec("wrch_mfc_cmd")
        check("MFC_Cmd" in line and "[ch21]" in line and "MFC GET" in line,
              f"wrch MFC_Cmd symbolic + [ch21] + MFC GET: {line}")
        sz, ins, line = dec("rdch_inmbox")
        check("SPU_RdInMbox" in line and "[ch29]" in line, f"rdch SPU_RdInMbox + [ch29]: {line}")
        sz, ins, line = dec("rchcnt_ps3_iso")
        check("SPU_IsoStat" in line and "[ch65]" in line, f"rchcnt SPU_IsoStat + [ch65]: {line}")

        # 13. dftsv bitmask auto-comment (0x62 = 0x40 NaN | 0x20 +Inf | 0x02 +Denorm)
        sz, ins, line = dec("dftsv_mask")
        check("NaN" in line and "+Inf" in line and "+Denorm" in line, f"dftsv mask comment: {line}")

        # 14. ilhu + iohl pair fusing
        dec("ilhu_pair")
        sz, ins, line = dec("iohl_pair")
        ida_auto.auto_wait()
        check("0x00001000" in line, f"ilhu+iohl comment: {line}")

        # 15. Alignment (4-byte multiple, never 2!)
        al_ea = m["align_seq"]
        al_sz = ida_idp.is_align_insn(al_ea)
        check(al_sz == 4 and (al_sz % 4) == 0, f"is_align_insn returns 4 (got {al_sz})")
        check(ida_idp.is_align_insn(al_ea + 2) == 0, "is_align_insn rejects unaligned +2")

        # 16. All 199 ISA instructions sweep
        base_199 = m["all199_start"]
        names_199 = m["all199_names"]
        bad_199 = []
        for idx, expected_mnem in enumerate(names_199):
            ea = base_199 + idx * 4
            ins = ida_ua.insn_t()
            sz = ida_ua.decode_insn(ins, ea)
            mn = ins.get_canon_mnem() if sz == 4 else "<FAIL>"
            if sz != 4 or mn != expected_mnem:
                bad_199.append(f"{expected_mnem}@0x{ea:X}->got {mn}(sz={sz})")
        check(len(bad_199) == 0, f"All 199 SPU ISA v1.2 instructions decoded accurately (bad={bad_199[:5]})")

    else:
        # Real-world IDB validation (lv0ldr or metldr)
        root = idc.get_root_filename().lower()
        seg = ida_segment.get_first_seg()
        while seg:
            ida_auto.plan_range(seg.start_ea, seg.end_ea)
            seg = ida_segment.get_next_seg(seg.start_ea)
        ida_auto.auto_wait()

        # Check shlhi
        shlhi_bad = 0
        shlhi_cnt = 0
        st_total = 0
        st_w = 0
        st_r = 0
        halt_bad = 0
        bisl_cnt = 0
        bisl_call = 0
        ch_sym_ok = 0
        ch_cnt = 0

        for ea in idautils.Heads():
            mn = idc.print_insn_mnem(ea)
            if mn == "shlhi":
                shlhi_cnt += 1
                ins = ida_ua.insn_t()
                ida_ua.decode_insn(ins, ea)
                if ins.Op3.type != ida_ua.o_imm or (0x7F < ins.Op3.value < 0xFFFFFF80):
                    shlhi_bad += 1
            elif mn in ("stqa", "stqr"):
                st_total += 1
                types = {xr.type for xr in idautils.XrefsFrom(ea, 0)}
                if ida_xref.dr_W in types: st_w += 1
                if ida_xref.dr_R in types: st_r += 1
            elif mn in ("heq", "heqi", "hgt", "hgti", "hlgt", "hlgti"):
                ins = ida_ua.insn_t()
                ida_ua.decode_insn(ins, ea)
                if ins.Op3.type != ida_ua.o_void:
                    halt_bad += 1
            elif mn == "bisl":
                bisl_cnt += 1
                if ida_idp.is_call_insn(ea):
                    bisl_call += 1
            elif mn in ("wrch", "rdch", "rchcnt"):
                ch_cnt += 1
                line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
                if "[ch" in line:
                    ch_sym_ok += 1

        check(shlhi_bad == 0, f"{root}: all {shlhi_cnt} shlhi decoded as RI7 (bad={shlhi_bad})")
        check(st_w == st_total and st_r == 0, f"{root}: all {st_total} stqa/stqr are dr_W (W={st_w}, R={st_r})")
        check(halt_bad == 0, f"{root}: all halt insns have 2 operands (bad={halt_bad})")
        check(bisl_call == bisl_cnt, f"{root}: all {bisl_cnt} bisl are calls ({bisl_call}/{bisl_cnt})")
        check(ch_cnt > 0 and ch_sym_ok == ch_cnt, f"{root}: all {ch_cnt} channel ops have [chN] auto-comment ({ch_sym_ok}/{ch_cnt})")

        if "lv0ldr" in root:
            # hbrr wrap fix
            hbrr_line = ida_lines.tag_remove(idc.generate_disasm_line(0x00FE0, 0) or "")
            check("0xFFFE26C0" not in hbrr_line and "226C0" in hbrr_line, f"lv0ldr:0x00FE0 hbrr fixed: {hbrr_line}")
            # Back-chain SP restore at 0x01608 -> spd == 0 at 0x0160C
            f = ida_funcs.get_func(0x01608)
            spd_before = ida_frame.get_spd(f, 0x01608) if f else None
            spd_after = ida_frame.get_spd(f, 0x0160C) if f else None
            check(spd_before == -144 and spd_after == 0,
                  f"lv0ldr:0x01608 lqd sp, 0(sp) SP restored ({spd_before} -> {spd_after})")
            # Switch tables
            si1 = ida_nalt.get_switch_info(0x19398)
            check(si1 is not None and si1.ncases == 7 and si1.jumps == 0x1939C and si1.defjump == 0x193D0 and si1.lowcase == 1,
                  f"lv0ldr:0x19398 switch recovered ({si1.ncases if si1 else None} cases)")
            si2 = ida_nalt.get_switch_info(0x1E090)
            check(si2 is not None and si2.ncases == 6 and si2.jumps == 0x1E094 and si2.defjump == 0x1E0E0 and si2.lowcase == 0,
                  f"lv0ldr:0x1E090 switch recovered ({si2.ncases if si2 else None} cases)")

        elif "metldr" in root:
            si = ida_nalt.get_switch_info(0x00770)
            check(si is not None and si.ncases == 7 and si.jumps == 0x774 and si.defjump == 0x7C8 and si.lowcase == 30,
                  f"metldr:0x00770 switch recovered ({si.ncases if si else None} cases, lowcase={si.lowcase if si else None})")

            # Verify spudec decompiles cleanly under native spu.dll!
            try:
                user_plugins = os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "plugins")
                if user_plugins and user_plugins not in sys.path:
                    sys.path.insert(0, user_plugins)
                import spudec
                set_elf_ea = idc.get_name_ea_simple("_ZN3lv010elf_access7set_elfEjj")
                if set_elf_ea == idc.BADADDR:
                    for ea_f in idautils.Functions():
                        nm = idc.get_func_name(ea_f)
                        if "set_elf" in nm:
                            set_elf_ea = ea_f
                            break
                check(set_elf_ea != idc.BADADDR, f"metldr: located set_elf @ 0x{set_elf_ea:X}")
                if set_elf_ea != idc.BADADDR:
                    fn_ir = spudec.decompile(set_elf_ea, check=True)
                    lines = spudec.pseudocode(fn_ir)
                    code_txt = "\n".join(lines)
                    check("0x7F" in code_txt and "0x7F7F7F7F" not in code_txt and not getattr(fn_ir, "problems", None),
                          f"spudec decompiles set_elf cleanly under spu.dll (lines={len(lines)})")
            except Exception as exc:
                check(False, f"spudec integration check raised: {exc}")

    result = {"mode": mode, "passed": passed, "failures": failures}
    if out_json:
        with open(out_json, "w") as f:
            json.dump(result, f, indent=2)
    else:
        for p in passed:
            print("  [PASS]", p)
        for f in failures:
            print("  [FAIL]", f)
        print(f"Summary: {len(passed)} passed, {len(failures)} failed")

    idc.qexit(0 if not failures else 1)


# ---------------------------------------------------------------------------
# Standalone driver
# ---------------------------------------------------------------------------
def run_standalone():
    idat = r"C:\Program Files\IDA Professional 9.5\idat.exe"
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--idat" and i + 2 < len(sys.argv):
            idat = sys.argv[i + 2]

    script_path = os.path.abspath(__file__)
    spudec_dir = os.path.abspath(os.path.join(os.path.dirname(script_path), "..", "..", "..", "plugins", "spudec"))
    lv0ldr_src = os.path.join(spudec_dir, "lv0ldr.dec.i64")
    metldr_src = os.path.join(spudec_dir, "metldr.356.sym.elf.i64")

    total_pass = 0
    total_fail = 0

    with tempfile.TemporaryDirectory(prefix="spu_val_") as tmp:
        # 1. Synthetic 199-instruction binary test
        bin_path = os.path.join(tmp, "synth_spu.bin")
        markers_path = os.path.join(tmp, "markers.json")
        out_synth = os.path.join(tmp, "out_synth.json")
        raw, markers = build_synthetic_binary()
        with open(bin_path, "wb") as f:
            f.write(raw)
        with open(markers_path, "w") as f:
            json.dump(markers, f)

        env = os.environ.copy()
        env["SPU_VAL_MODE"] = "synthetic"
        env["SPU_VAL_MARKERS"] = markers_path
        env["SPU_VAL_OUT"] = out_synth

        print("=== [1/3] Synthetic 199-instruction & edge-case binary ===", flush=True)
        synth_log = os.path.join(tmp, "synth.log")
        subprocess.run([idat, "-c", "-A", "-pspu", "-b0", f"-L{synth_log}", f"-S{script_path}", bin_path],
                       env=env, check=False, timeout=45)
        if not os.path.exists(out_synth):
            if os.path.exists(synth_log):
                print(open(synth_log, "r", errors="replace").read()[-2000:], flush=True)
            raise RuntimeError("Synthetic IDA test did not produce output JSON")
        with open(out_synth, "r") as f:
            res = json.load(f)
        for p in res["passed"]:
            print("  [PASS]", p, flush=True)
        for fl in res["failures"]:
            print("  [FAIL]", fl, flush=True)
        total_pass += len(res["passed"])
        total_fail += len(res["failures"])

        # 2. Real-world lv0ldr.dec.i64 (scratch copy)
        if os.path.exists(lv0ldr_src):
            print("\n=== [2/3] Real-world lv0ldr.dec.i64 (scratch copy) ===", flush=True)
            lv_copy = os.path.join(tmp, "lv0ldr_copy.i64")
            out_lv = os.path.join(tmp, "out_lv.json")
            lv_log = os.path.join(tmp, "lv.log")
            shutil.copy2(lv0ldr_src, lv_copy)
            env["SPU_VAL_MODE"] = "idb"
            env["SPU_VAL_OUT"] = out_lv
            subprocess.run([idat, "-A", f"-L{lv_log}", f"-S{script_path}", lv_copy],
                           env=env, check=False, timeout=60)
            if not os.path.exists(out_lv):
                if os.path.exists(lv_log):
                    print(open(lv_log, "r", errors="replace").read()[-2000:], flush=True)
                raise RuntimeError("lv0ldr IDA test did not produce output JSON")
            with open(out_lv, "r") as f:
                res = json.load(f)
            for p in res["passed"]:
                print("  [PASS]", p, flush=True)
            for fl in res["failures"]:
                print("  [FAIL]", fl, flush=True)
            total_pass += len(res["passed"])
            total_fail += len(res["failures"])

        # 3. Real-world metldr.356.sym.elf.i64 (scratch copy + spudec check)
        if os.path.exists(metldr_src):
            print("\n=== [3/3] Real-world metldr.356.sym.elf.i64 (scratch copy + spudec) ===", flush=True)
            ml_copy = os.path.join(tmp, "metldr_copy.i64")
            out_ml = os.path.join(tmp, "out_ml.json")
            ml_log = os.path.join(tmp, "ml.log")
            shutil.copy2(metldr_src, ml_copy)
            env["SPU_VAL_MODE"] = "idb"
            env["SPU_VAL_OUT"] = out_ml
            subprocess.run([idat, "-A", f"-L{ml_log}", f"-S{script_path}", ml_copy],
                           env=env, check=False, timeout=60)
            if not os.path.exists(out_ml):
                if os.path.exists(ml_log):
                    print(open(ml_log, "r", errors="replace").read()[-2000:], flush=True)
                raise RuntimeError("metldr IDA test did not produce output JSON")
            with open(out_ml, "r") as f:
                res = json.load(f)
            for p in res["passed"]:
                print("  [PASS]", p, flush=True)
            for fl in res["failures"]:
                print("  [FAIL]", fl, flush=True)
            total_pass += len(res["passed"])
            total_fail += len(res["failures"])

    print(f"\n========================================")
    print(f"TOTAL: {total_pass} passed, {total_fail} failed")
    print(f"========================================")
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    try:
        import ida_idp  # noqa: F401
        in_ida = True
    except ImportError:
        in_ida = False

    if in_ida:
        import traceback
        import idc
        try:
            run_inside_ida()
        except BaseException:
            traceback.print_exc()
            idc.qexit(2)
    else:
        run_standalone()
