/*
 * Cell Broadband Engine SPU / CBEA Type Library header (spu_cbea.til)
 * Defines architectural 128-bit SIMD vector types, MFC DMA structures,
 * and standard SPU channel/status constants for IDA Pro & spudec.
 */

#ifndef __SPU_CBEA_H
#define __SPU_CBEA_H

typedef signed char        s8;
typedef unsigned char      u8;
typedef signed short       s16;
typedef unsigned short     u16;
typedef signed int         s32;
typedef unsigned int       u32;
typedef signed long long   s64;
typedef unsigned long long u64;

typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef signed short       int16_t;
typedef unsigned short     uint16_t;
typedef signed int         int32_t;
typedef unsigned int       uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;
typedef unsigned int       size_t;
typedef int                ssize_t;
typedef unsigned int       uintptr_t;
typedef int                intptr_t;

/* 128-bit SPU Quadword & SIMD Vector Types (16-byte aligned, big-endian) */
typedef struct __attribute__((aligned(16))) {
    u8 b[16];
} qword;

typedef struct __attribute__((aligned(16))) {
    u8 v[16];
} vec_uchar16;

typedef struct __attribute__((aligned(16))) {
    s8 v[16];
} vec_char16;

typedef struct __attribute__((aligned(16))) {
    u16 v[8];
} vec_ushort8;

typedef struct __attribute__((aligned(16))) {
    s16 v[8];
} vec_short8;

typedef struct __attribute__((aligned(16))) {
    u32 v[4];
} vec_uint4;

typedef struct __attribute__((aligned(16))) {
    s32 v[4];
} vec_int4;

typedef struct __attribute__((aligned(16))) {
    u64 v[2];
} vec_ullong2;

typedef struct __attribute__((aligned(16))) {
    s64 v[2];
} vec_llong2;

typedef struct __attribute__((aligned(16))) {
    float v[4];
} vec_float4;

typedef struct __attribute__((aligned(16))) {
    double v[2];
} vec_double2;

/* Unaligned qword helper used by spudec */
typedef struct {
    u8 b[16];
} qword_unaligned;

/* CBEA MFC DMA List Element (8 bytes, big-endian) */
typedef struct {
    u16 notify_reserved; /* bit 0: stall-and-notify, bits 1..15: reserved */
    u16 size;            /* transfer size in bytes (max 16384) */
    u32 eal;             /* lower 32 bits of Effective Address */
} mfc_list_element_t;

/* CBEA SPU Channel Numbers */
enum spu_channel_id_t {
    CH_SPU_RdEventStat     = 0,
    CH_SPU_WrEventMask     = 1,
    CH_SPU_WrEventAck      = 2,
    CH_SPU_RdSigNotify1    = 3,
    CH_SPU_RdSigNotify2    = 4,
    CH_SPU_WrDec           = 7,
    CH_SPU_RdDec           = 8,
    CH_MFC_WrMSSyncReq     = 9,
    CH_SPU_RdEventMask     = 11,
    CH_MFC_RdTagMask       = 12,
    CH_SPU_RdMachStat      = 13,
    CH_SPU_WrSRR0          = 14,
    CH_SPU_RdSRR0          = 15,
    CH_MFC_LSA             = 16,
    CH_MFC_EAH             = 17,
    CH_MFC_EAL             = 18,
    CH_MFC_Size            = 19,
    CH_MFC_TagID           = 20,
    CH_MFC_Cmd             = 21,
    CH_MFC_WrTagMask       = 22,
    CH_MFC_WrTagUpdate     = 23,
    CH_MFC_RdTagStat       = 24,
    CH_MFC_RdListStallStat = 25,
    CH_MFC_WrListStallAck  = 26,
    CH_MFC_RdAtomicStat    = 27,
    CH_SPU_WrOutMbox       = 28,
    CH_SPU_RdInMbox        = 29,
    CH_SPU_WrOutIntrMbox   = 30,
    CH_SPU_IsoCntl         = 64,
    CH_SPU_IsoStat         = 65,
    CH_SPU_IsoRootKey      = 66,
    CH_SPU_IsoKey          = 67,
    CH_SPU_IsoIdent        = 68
};

/* CBEA MFC Command Opcodes */
enum spu_mfc_cmd_t {
    MFC_PUT_CMD       = 0x20,
    MFC_PUTS_CMD      = 0x21,
    MFC_PUTR_CMD      = 0x22,
    MFC_PUTB_CMD      = 0x24,
    MFC_PUTBS_CMD     = 0x25,
    MFC_PUTRB_CMD     = 0x26,
    MFC_PUTF_CMD      = 0x28,
    MFC_PUTFS_CMD     = 0x29,
    MFC_PUTRF_CMD     = 0x2A,
    MFC_GET_CMD       = 0x40,
    MFC_GETS_CMD      = 0x41,
    MFC_GETB_CMD      = 0x44,
    MFC_GETBS_CMD     = 0x45,
    MFC_GETF_CMD      = 0x48,
    MFC_GETFS_CMD     = 0x49,
    MFC_PUTL_CMD      = 0x50,
    MFC_PUTLB_CMD     = 0x54,
    MFC_PUTLF_CMD     = 0x58,
    MFC_GETL_CMD      = 0x60,
    MFC_GETLB_CMD     = 0x64,
    MFC_GETLF_CMD     = 0x68,
    MFC_SNDSIG_CMD    = 0xA0,
    MFC_SNDSIGB_CMD   = 0xA4,
    MFC_SNDSIGF_CMD   = 0xA8,
    MFC_GETLLAR_CMD   = 0xB0,
    MFC_PUTLLC_CMD    = 0xB4,
    MFC_PUTLLUC_CMD   = 0xB8,
    MFC_PUTQLLUC_CMD  = 0xBC,
    MFC_EIEIO_CMD     = 0xC0,
    MFC_SYNC_CMD      = 0xC8,
    MFC_BARRIER_CMD   = 0xCC
};

/* CBEA Tag Update Modes (MFC_WrTagUpdate, ch23) */
enum mfc_tag_update_t {
    MFC_TAG_UPDATE_IMMEDIATE = 0,
    MFC_TAG_UPDATE_ANY       = 1,
    MFC_TAG_UPDATE_ALL       = 2
};

/* Common SPU C runtime prototypes */
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int   strcmp(const char *a, const char *b);
int   strncmp(const char *a, const char *b, size_t n);

#endif /* __SPU_CBEA_H */
