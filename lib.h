#ifndef LIB_H
#define LIB_H

#include <stdint.h>

typedef struct {     /* little endian */
  uint32_t c;        /* characteristic */
  uint32_t oid;      /* original trainer id number */
  uint8_t  name[10]; /* Pokemon's nickname */
  uint16_t lang;
  uint8_t  oname[7]; /* original trainer id name.
                      * The characters represented by each byte are determined
                      * by proprietary character set. */
  uint8_t  mark;     /* markings */
  uint16_t chk;      /* check sum */
  uint16_t _1;       /* unknown */
  struct {           /* encrypted data */
    struct {            /* growth */
      uint16_t species;
      uint16_t held;
      uint32_t exp;
      uint8_t  ppb;     /* power points bonuses */
      uint8_t  friend;
      uint16_t _1;
    } g;
    struct {            /* attack */
      uint16_t mov[4];
      uint8_t  pp[4];
    } a;
    struct {            /* effort values & conditions */
      uint8_t  hp;
      uint8_t  atk;     /* attack */
      uint8_t  def;     /* defense */
      uint8_t  spd;     /* speed */
      uint8_t  satk;    /* special attack */
      uint8_t  sdef;    /* special defense */
      uint8_t  cool;    /* coolness */
      uint8_t  beauty;  /* beauty */
      uint8_t  cute;    /* cuteness */
      uint8_t  smart;   /* smartness */
      uint8_t  tough;   /* toughness */
      uint8_t  feel;    /* feel */
    } e;
    struct {            /* miscellaneous */
      uint8_t  virus;   /* pokemon virus status */
      uint8_t  met;     /* met location */
      uint16_t ori;     /* origin info */
      uint32_t iv;
      uint32_t r;
    } m;
  } dat;
  uint32_t stat;     /* status condition */
  uint8_t  lv;
  uint8_t  remain;
  uint16_t hp;       /* current health point */
  uint16_t thp;      /* total health point */
  uint16_t atk;      /* attack */
  uint16_t def;      /* defense */
  uint16_t spd;      /* speed */
  uint16_t satk;     /* special attack */
  uint16_t sdef;     /* special defense */
} mon_t;

uint16_t mchk(mon_t * mon);
int      mdec(mon_t * mon);
void     menc(mon_t * mon);
void     mhexshow(mon_t * mon);
void     mtest(void);

typedef struct {
  int type;
  void * addr;
} vptr_t;

typedef struct {
  vptr_t mon;
} vpok_t;

typedef struct {
  vpok_t rs_jp; /* ruby/sapphire jp */
  vpok_t rs_en; /* ruby/sapphire en */
  vpok_t fl_jp; /* fire/leaf jp */
  vpok_t fl_en; /* fire/leaf en */
  vpok_t e_jp;  /* emarald jp */
  vpok_t e_en;  /* emarald en */
} vref_t;

vref_t * getref(void);

#endif
