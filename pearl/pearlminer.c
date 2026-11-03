// pearlminer.c — PEARL (PearlMiningV2, BSC 0x7E2DA878217EB995F9e5d36eD32c9Cea52442681) proof grinder.
// Finds nonces with uint256(keccak256(abi.encode(bytes32 seed, uint256 nonce))) <= target.
// Keccak-f[1600] core copied VERBATIM from ~/workspace/hashore-vet/hashore.c (production-proven core).
// Nonce layout: nonce = (shard << 56) + counter  (u64 nonces; disjoint shards => disjoint ranges).
// Found lines are appended to --out as "<nonce> <digest_hex>" and also printed to stdout as
// "PEARLFOUND <nonce> <digest_hex>" for log-based harvesting. Progress checkpoint in --prog file.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static const uint64_t RC[24] = {
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int ROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

#define ROTL(x,n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf(uint64_t st[25]) {
  uint64_t bc[5], t;
  for (int r = 0; r < 24; r++) {
    for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
    for (int i = 0; i < 5; i++) { t = bc[(i+4)%5] ^ ROTL(bc[(i+1)%5], 1); for (int j = 0; j < 25; j += 5) st[j+i] ^= t; }
    t = st[1];
    for (int i = 0; i < 24; i++) { int j = PILN[i]; uint64_t tmp = st[j]; st[j] = ROTL(t, ROTC[i]); t = tmp; }
    for (int j = 0; j < 25; j += 5) {
      uint64_t row[5]; for (int i = 0; i < 5; i++) row[i] = st[j+i];
      for (int i = 0; i < 5; i++) st[j+i] = row[i] ^ ((~row[(i+1)%5]) & row[(i+2)%5]);
    }
    st[0] ^= RC[r];
  }
}

// keccak-256 of msg (len < 136 -> single block), digest out (32 bytes, big-endian hex order)
static void keccak256(const uint8_t *msg, size_t len, uint8_t out[32]) {
  uint64_t st[25] = {0};
  uint8_t block[136] = {0};
  memcpy(block, msg, len);
  block[len] = 0x01;
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

static void tohex(const uint8_t *d, char *hex) { for (int i = 0; i < 32; i++) sprintf(hex + 2*i, "%02x", d[i]); hex[64] = 0; }

static int parse_hex32(const char *s, uint8_t out[32]) {
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  if (strlen(s) != 64) return -1;
  for (int i = 0; i < 32; i++) { unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) return -1; out[i] = (uint8_t)v; }
  return 0;
}

static void write_prog(const char *path, uint64_t next_counter) {
  char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
  FILE *f = fopen(tmp, "w"); if (!f) return;
  fprintf(f, "%llu\n", (unsigned long long)next_counter); fclose(f);
  rename(tmp, path);
}

int main(int argc, char **argv) {
  // SELFTEST 1: empty-string Keccak-256 vector (mandatory per miner-validation rule)
  uint8_t out[32]; char hex[65];
  keccak256((const uint8_t*)"", 0, out); tohex(out, hex);
  if (strcmp(hex, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") != 0) {
    fprintf(stderr, "SELFTEST FAIL: keccak256(\"\") = %s\n", hex); return 1;
  }
  const char *seed_h = NULL, *target_h = NULL, *out_path = NULL, *prog_path = NULL, *expect0 = NULL;
  uint64_t shard = 0; long timelimit = 3600; long maxfound = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--seed") && i+1 < argc) seed_h = argv[++i];
    else if (!strcmp(argv[i], "--target") && i+1 < argc) target_h = argv[++i];
    else if (!strcmp(argv[i], "--shard") && i+1 < argc) shard = strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--out") && i+1 < argc) out_path = argv[++i];
    else if (!strcmp(argv[i], "--prog") && i+1 < argc) prog_path = argv[++i];
    else if (!strcmp(argv[i], "--timelimit") && i+1 < argc) timelimit = atol(argv[++i]);
    else if (!strcmp(argv[i], "--maxfound") && i+1 < argc) maxfound = atol(argv[++i]);
    else if (!strcmp(argv[i], "--expect0") && i+1 < argc) expect0 = argv[++i];
    else if (!strcmp(argv[i], "--digest-of")) {
      // utility: print digest for one nonce and exit (used by harness cross-checks)
      uint64_t n = strtoull(argv[i+1], NULL, 10); i++;
      uint8_t seed[32]; if (!seed_h || parse_hex32(seed_h, seed)) { fprintf(stderr, "need --seed\n"); return 2; }
      uint8_t msg[64]; memcpy(msg, seed, 32); memset(msg+32, 0, 32);
      for (int b = 0; b < 8; b++) msg[56+b] = (uint8_t)(n >> (56 - 8*b));
      keccak256(msg, 64, out); tohex(out, hex); printf("%s\n", hex); return 0;
    }
    else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
  }
  uint8_t seed[32], target[32];
  if (!seed_h || parse_hex32(seed_h, seed)) { fprintf(stderr, "bad --seed\n"); return 2; }
  if (!target_h || parse_hex32(target_h, target)) { fprintf(stderr, "bad --target\n"); return 2; }
  // SELFTEST 2: digest(seed || nonce 0) must equal the on-chain proofDigest(wallet, 0)
  if (expect0) {
    uint8_t msg[64]; memcpy(msg, seed, 32); memset(msg+32, 0, 32);
    keccak256(msg, 64, out); tohex(out, hex);
    const char *e = expect0; if (e[0]=='0' && e[1]=='x') e += 2;
    if (strcmp(hex, e) != 0) { fprintf(stderr, "SELFTEST FAIL: digest(seed||0)=%s != chain %s\n", hex, e); return 1; }
    fprintf(stderr, "selftest ok (empty vector + chain proofDigest nonce 0)\n");
  }
  uint64_t counter = 0;
  if (prog_path) { FILE *f = fopen(prog_path, "r"); if (f) { if (fscanf(f, "%llu", (unsigned long long*)&counter) != 1) counter = 0; fclose(f); } }
  FILE *outf = out_path ? fopen(out_path, "a") : stdout;
  if (!outf) { fprintf(stderr, "cannot open out\n"); return 2; }
  uint8_t msg[64], digest[32];
  memcpy(msg, seed, 32); memset(msg + 32, 0, 32);
  time_t t0 = time(NULL); uint64_t tried = 0, found = 0; time_t last_prog = t0;
  while (time(NULL) - t0 < timelimit) {
    uint64_t nonce = (shard << 56) + counter;
    for (int b = 0; b < 8; b++) msg[56+b] = (uint8_t)(nonce >> (56 - 8*b));
    keccak256(msg, 64, digest);
    tried++; counter++;
    if (memcmp(digest, target, 32) <= 0) {
      char dh[65]; tohex(digest, dh);
      fprintf(outf, "%llu %s\n", (unsigned long long)nonce, dh); fflush(outf);
      printf("PEARLFOUND %llu %s\n", (unsigned long long)nonce, dh); fflush(stdout);
      found++;
      if (maxfound && (long)found >= maxfound) break;
    }
    if ((tried & 0xFFFFF) == 0) {  // ~every 1M hashes
      time_t now = time(NULL);
      if (prog_path && now - last_prog >= 5) { write_prog(prog_path, counter); last_prog = now; }
      if (now - t0 >= 30 && (tried % (0xFFFFF * 8)) < 0x100000) {
        fprintf(stderr, "shard %llu: tried=%llu found=%llu rate=%.2f MH/s\n", (unsigned long long)shard,
                (unsigned long long)tried, (unsigned long long)found,
                (double)tried / ((now - t0) * 1e6)); fflush(stderr);
      }
    }
  }
  if (prog_path) write_prog(prog_path, counter);
  fprintf(stderr, "shard %llu done: tried=%llu found=%llu elapsed=%lds\n", (unsigned long long)shard,
          (unsigned long long)tried, (unsigned long long)found, (long)(time(NULL) - t0));
  if (outf != stdout) fclose(outf);
  return 0;
}
