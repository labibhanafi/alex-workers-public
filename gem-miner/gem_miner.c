// GEM (GemCoin) PoW miner — built 2026-11-11 from verified GemCoin.sol (Sourcify exact_match).
// puzzleHash(wallet, nonce) = uint256(keccak256(abi.encode(epochSeed, wallet, nonce)))
//   = 96-byte message: seed(32) || wallet(32 left-padded) || nonce(32 BE). One keccak block (rate 136).
// Valid proof: digest (uint256 BE) <= epochTarget.
// Keccak-f core copied VERBATIM via keccak_core.inc (from hashore.c; never retyped).
// Usage:
//   gem_miner selftest
//   gem_miner digest <seed_hex64> <wallet_hex40> <nonce_dec>
//   gem_miner mine <seed_hex64> <wallet_hex40> <target_hex64> <nonce_base_dec> <max_found> <threads>
//     -> prints "FOUND <nonce_dec>" per proof (stdout, line-flushed), "DONE hashes=<n>" on stderr at exit.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#include "keccak_core.inc"

static void keccak256_generic(const uint8_t *msg, size_t len, uint8_t out[32]) {
  uint64_t st[25] = {0};
  size_t off = 0;
  while (len - off >= 136) {
    for (int i = 0; i < 17; i++) {
      uint64_t lane = 0;
      for (int b = 0; b < 8; b++) lane |= ((uint64_t)msg[off + i*8 + b]) << (8*b);
      st[i] ^= lane;
    }
    keccakf(st);
    off += 136;
  }
  uint8_t block[136] = {0};
  size_t rem = len - off;
  memcpy(block, msg + off, rem);
  block[rem] = 0x01;
  block[135] |= 0x80;
  for (int i = 0; i < 17; i++) {
    uint64_t lane = 0;
    for (int b = 0; b < 8; b++) lane |= ((uint64_t)block[i*8+b]) << (8*b);
    st[i] ^= lane;
  }
  keccakf(st);
  for (int i = 0; i < 4; i++)
    for (int b = 0; b < 8; b++) out[i*8+b] = (uint8_t)(st[i] >> (8*b));
}

static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; }
static void parse_hex(const char *s, uint8_t *out, size_t n) {
  if (s[0]=='0'&&(s[1]=='x'||s[1]=='X')) s+=2;
  for (size_t i=0;i<n;i++) out[i]=(uint8_t)((hexval(s[2*i])<<4)|hexval(s[2*i+1]));
}
static void print_hex(const uint8_t *b, size_t n){ for(size_t i=0;i<n;i++) printf("%02x", b[i]); }

// digest for (seed, wallet, nonce): message = seed || pad24||wallet || nonceBE
static void gem_digest(const uint8_t seed[32], const uint8_t wallet20[20], uint64_t nonce, uint8_t out[32]) {
  uint8_t msg[96];
  memcpy(msg, seed, 32);
  memset(msg+32, 0, 12);
  memcpy(msg+44, wallet20, 20);
  for (int i=0;i<24;i++) msg[64+i]=0;
  for (int i=0;i<8;i++) msg[88+i]=(uint8_t)(nonce >> (8*(7-i)));
  keccak256_generic(msg, 96, out);
}

// ---- mining: single-block fast path ----
// lanes 0..3 = seed, 4..7 = wallet padded (lane4 = 0, lane5 = 0, lane6 high4=0|wallet[0..3]... computed at init),
// lane 8..10 = 0 (nonce < 2^64), lane 11 = bswap64(nonce), lane 12 ^= 0x01 (padding), lane 16 ^= 0x80<<56.
static uint64_t PRE[25];
static uint64_t TGT[4]; // target as 4 BE uint64 words of the 32-byte BE value
static atomic_int g_found;
static atomic_long g_hashes;
static int g_maxfound;
static uint64_t g_base;

static int digest_le_target(const uint64_t st[25]) {
  // output bytes: lane i LE bytes = digest bytes i*8.. ; uint256 BE compare: word0 = bytes 0..7 BE
  for (int w=0; w<4; w++) {
    uint64_t lane = st[w];
    uint64_t be = __builtin_bswap64(lane); // digest bytes w*8..w*8+7 as BE uint64
    if (be < TGT[w]) return 1;
    if (be > TGT[w]) return 0;
  }
  return 1; // equal
}

static void *worker(void *arg) {
  long tid = (long)arg;
  uint64_t nonce = g_base + (uint64_t)tid * (1ULL<<44);
  long local = 0;
  while (atomic_load(&g_found) < g_maxfound) {
    uint64_t st[25];
    memcpy(st, PRE, sizeof(PRE));
    st[11] = __builtin_bswap64(nonce);
    keccakf(st);
    local++;
    if (digest_le_target(st)) {
      int f = atomic_fetch_add(&g_found, 1) + 1;
      if (f <= g_maxfound) { printf("FOUND %llu\n", (unsigned long long)nonce); fflush(stdout); }
    }
    nonce++;
    if ((local & 0xFFFF) == 0) atomic_fetch_add(&g_hashes, 0x10000);
  }
  atomic_fetch_add(&g_hashes, local & 0xFFFF);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "selftest") == 0) {
    uint8_t out[32];
    keccak256_generic((const uint8_t*)"", 0, out);
    printf("keccak256(\"\") = "); print_hex(out, 32); printf("\n");
    keccak256_generic((const uint8_t*)"abc", 3, out);
    printf("keccak256(\"abc\") = "); print_hex(out, 32); printf("\n");
    return 0;
  }
  if (argc >= 5 && strcmp(argv[1], "digest") == 0) {
    uint8_t seed[32], wal[20];
    parse_hex(argv[2], seed, 32);
    parse_hex(argv[3], wal, 20);
    uint64_t nonce = strtoull(argv[4], NULL, 10);
    uint8_t out[32];
    gem_digest(seed, wal, nonce, out);
    printf("0x"); print_hex(out, 32); printf("\n");
    return 0;
  }
  if (argc >= 8 && strcmp(argv[1], "mine") == 0) {
    uint8_t seed[32], wal[20], tgt[32];
    parse_hex(argv[2], seed, 32);
    parse_hex(argv[3], wal, 20);
    parse_hex(argv[4], tgt, 32);
    for (int w=0; w<4; w++) { uint64_t v=0; for(int b=0;b<8;b++) v=(v<<8)|tgt[w*8+b]; TGT[w]=v; }
    g_base = strtoull(argv[5], NULL, 10);
    g_maxfound = atoi(argv[6]);
    int nthreads = atoi(argv[7]);
    // build PRE: absorb lanes for seed||walletpad, padding lanes; nonce lanes zero except lane 11 set per-iter
    uint8_t block[136] = {0};
    memcpy(block, seed, 32);
    memcpy(block+44, wal, 20);
    block[96] = 0x01;
    block[135] |= 0x80;
    for (int i=0;i<17;i++) { uint64_t lane=0; for(int b=0;b<8;b++) lane |= ((uint64_t)block[i*8+b])<<(8*b); PRE[i]=lane; }
    for (int i=17;i<25;i++) PRE[i]=0;
    atomic_init(&g_found, 0);
    atomic_init(&g_hashes, 0);
    pthread_t th[64];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i=0;i<nthreads;i++) pthread_create(&th[i], NULL, worker, (void*)i);
    for (int i=0;i<nthreads;i++)pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec-t0.tv_sec) + (t1.tv_nsec-t0.tv_nsec)/1e9;
    fprintf(stderr, "DONE hashes=%ld secs=%.2f mhs=%.2f\n", atomic_load(&g_hashes), dt, dt>0 ? atomic_load(&g_hashes)/dt/1e6 : 0);
    return 0;
  }
  fprintf(stderr, "usage: selftest | digest <seed> <wallet> <nonce> | mine <seed> <wallet> <target> <base> <maxfound> <threads>\n");
  return 1;
}
