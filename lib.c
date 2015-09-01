#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "lib.h"

#define LANG_JAPANESE 0x201
#define LANG_ENGLISH  0x202
#define LANG_FRENCH   0x203
#define LANG_ITALIAN  0x204
#define LANG_GERMAN   0x205
#define LANG_KOREAN   0x206
#define LANG_SPANISH  0x207

void
mxor(mon_t * mon) {
  uint32_t * buf = (uint32_t *) &mon->dat;
  uint32_t key = mon->c ^ mon->oid;
  uint32_t len = sizeof(mon->dat) / sizeof(uint32_t);
  while (len--) buf[len] = buf[len] ^ key;
}

#define OFFSETOF(type, field) ((size_t) &((type *) 0)->field)
#define FIELDOF(type, field) { \
  OFFSETOF(type, field), sizeof(((type *) 0)->field) \
}
#define MLEN 4
#define MBASE OFFSETOF(mon_t, dat)
#define MFIELDS { \
  FIELDOF(mon_t, dat.g), \
  FIELDOF(mon_t, dat.a), \
  FIELDOF(mon_t, dat.e), \
  FIELDOF(mon_t, dat.m) \
}

void
mreo(mon_t * mon, int set) { /* reorder */
  mon_t ret;
  size_t dec, enc = MBASE, size;
  size_t field[MLEN][2] = MFIELDS;
  size_t f, r, q, i;                    /* r := f * q + r */
  for (f = 1, i = MLEN; i; i--) f *= i; /* f := MLEN! (factorial) */
  for (r = mon->c % f, i = MLEN; i; i--, r %= f) {
    dec = field[q = r / (f /= i)][0], size = field[q][1];
    memmove(field + q, field + q + 1, (i - q - 1) * sizeof(* field));
    if (set) memcpy((uint8_t *) &ret + enc, (uint8_t *) mon + dec, size);
    else     memcpy((uint8_t *) &ret + dec, (uint8_t *) mon + enc, size);
    enc += size;
  }
  mon->dat = ret.dat;
}

uint16_t
mchk(mon_t * mon) {
  uint16_t chk = 0;
  size_t i;
  for (i = 0; i < sizeof(mon->dat)/sizeof(uint16_t); i++)
    chk += i[(uint16_t *) &mon->dat];
  return chk;
}

int
mdec(mon_t * mon) {
  mxor(mon);
  mreo(mon, 0);
  return mon->chk != mchk(mon);
}

void
menc(mon_t * mon) {
  mon->chk = mchk(mon);
  mreo(mon, 1);
  mxor(mon);
}

#define LEN(field) (sizeof(field) / sizeof(* field))

void
mhexshow(mon_t * mon) {
  size_t i;
  printf("characteristic:         0x%08X\n",      mon->c);
  printf("original trainer id:    0x%08X\n",      mon->oid);
  printf("nickname:               0x");
  for (i = 0; i < LEN(mon->name); i++)
    printf("%02X",                                mon->name[i]);
  putchar('\n');
  printf("language:               0x%04X\n",      mon->lang);
  printf("original trainer name:  0x");
  for (i = 0; i < LEN(mon->oname); i++)
    printf("%02X",                                mon->oname[i]);
  putchar('\n');
  printf("markings:               0x%02X\n",      mon->mark);
  printf("checksum:               0x%04X\n",      mon->chk);
  printf("_unknown:               0x%04X\n",      mon->_1);
  printf("species:                0x%04X\n",      mon->dat.g.species);
  printf("item held:              0x%04X\n",      mon->dat.g.held);
  printf("experience:             %" PRIu32 "\n", mon->dat.g.exp);
  printf("power points bonuses:   %" PRIu8 "\n",  mon->dat.g.ppb);
  printf("friend:                 %" PRIu8 "\n",  mon->dat.g.friend);
  printf("_unknown:               0x%04X\n",      mon->dat.g._1);
  for (i = 0; i < LEN(mon->dat.a.mov); i++)
    printf("move %" PRIuPTR ":"
           "                 0x%04X\n", i + 1,    mon->dat.a.mov[i]);
  for (i = 0; i < LEN(mon->dat.a.pp); i++)
    printf("power points %" PRIuPTR ":"
           "         %" PRIu8 "\n",     i + 1,    mon->dat.a.pp[i]);
  printf("effort health points:   %" PRIu8 "\n",  mon->dat.e.hp);
  printf("effort attack:          %" PRIu8 "\n",  mon->dat.e.atk);
  printf("effort defense:         %" PRIu8 "\n",  mon->dat.e.def);
  printf("effort speed:           %" PRIu8 "\n",  mon->dat.e.spd);
  printf("effort special attack:  %" PRIu8 "\n",  mon->dat.e.satk);
  printf("effort special defense: %" PRIu8 "\n",  mon->dat.e.sdef);
  printf("coolness:               %" PRIu8 "\n",  mon->dat.e.cool);
  printf("beauty:                 %" PRIu8 "\n",  mon->dat.e.beauty);
  printf("cute:                   %" PRIu8 "\n",  mon->dat.e.cute);
  printf("smart:                  %" PRIu8 "\n",  mon->dat.e.smart);
  printf("tough:                  %" PRIu8 "\n",  mon->dat.e.tough);
  printf("feel:                   %" PRIu8 "\n",  mon->dat.e.feel);
  printf("pokemon virus status:   0x%02X\n",      mon->dat.m.virus);
  printf("met location:           0x%02X\n",      mon->dat.m.met);
  printf("origin info:            0x%04X\n",      mon->dat.m.ori);
  printf("ivs, egg, and ability:  0x%08X\n",      mon->dat.m.iv);
  printf("ribbons and obedience:  0x%08X\n",      mon->dat.m.r);
  printf("status condition:       0x%08X\n",      mon->stat);
  printf("level:                  %" PRIu8 "\n",  mon->lv);
  printf("remain:                 0x%02X\n",      mon->remain);
  printf("current health point:   %" PRIu16 "\n", mon->hp);
  printf("total health point:     %" PRIu16 "\n", mon->thp);
  printf("attack:                 %" PRIu16 "\n", mon->atk);
  printf("defense:                %" PRIu16 "\n", mon->def);
  printf("speed:                  %" PRIu16 "\n", mon->spd);
  printf("special attack:         %" PRIu16 "\n", mon->satk);
  printf("special defense:        %" PRIu16 "\n", mon->sdef);
}

void
mtest(void) {
  uint8_t src[100] =
      "\x12""\xdc" "\x54""\xc4" "\x55""\x6b" "\x8a""\x59"
      "\x6e""\x7b" "\xff""\xff" "\xff""\xff" "\x00""\x00"
      "\x00""\x00" "\x01""\x02" "\x0b""\x0a" "\xff""\xff"
      "\xff""\xff" "\x00""\x00" "\xd2""\xea" "\x00""\x00"
      "\x71""\xb6" "\xde""\x9d" "\xbb""\xd1" "\xde""\x9d"
      "\x47""\x48" "\xde""\x9d" "\x81""\x0b" "\xde""\xe1"
      "\x47""\xb7" "\xde""\x9d" "\x47""\xb7" "\xde""\x9d"
      "\x56""\xb7" "\xe9""\x9d" "\xf1""\xb7" "\xe8""\x9d"
      "\x64""\xae" "\xd4""\x80" "\x47""\xa5" "\x5d""\xbc"
      "\x8a""\x64" "\xf7""\x91" "\x47""\xb7" "\xde""\x9d"
      "\x00""\x00" "\x00""\x00" "\x1d""\xff" "\x59""\x00"
      "\x5b""\x00" "\x38""\x00" "\x44""\x00" "\x39""\x00"
      "\x30""\x00" "\x33""\x00";
  mon_t mon;
  memcpy(&mon, src, sizeof(src));
  mdec(&mon);
  mhexshow(&mon);
}

#define VDIRECT  0
#define VPOINTER 1

vref_t *
getref(void) {
  static vref_t ref = {
    .rs_jp = {
      .mon = {VDIRECT, (void *) 0x03004290}
    },
    .rs_en = {
      .mon = {VDIRECT, (void *) 0x03004360}
    },
    .fl_jp = {
      .mon = {VDIRECT, (void *) 0x020241E4}
    },
    .fl_en = {
      .mon = {VDIRECT, (void *) 0x02024284}
    },
    .e_jp = {
      .mon = {VDIRECT, (void *) 0x02024190}
    },
    .e_en = {
      .mon = {VDIRECT, (void *) 0x020244EC}
    }
  };
  return &ref;
}
