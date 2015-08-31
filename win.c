#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <windows.h>
#include "lib.h"

uint32_t
getpid(int argc, char ** argv) {
  char * num = argv[1];
  uint32_t pid = 0;
  size_t i;
  if (argc != 2) {
    puts("should specify pid");
    puts("eg: ./win.exe 1234");
    exit(1);
  }
  for (i = 0; num[i]; i++)
    pid = pid * 10 + num[i] - '0';
  return pid;
}

void *
getphd(uint32_t pid) {
  void * phd = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                           PROCESS_VM_OPERATION, 0, pid);
  if (phd == 0) {
    printf("no process %" PRIu32 " found\n", pid);
    exit(1);
  }
  printf("open process %" PRIu32 "\n", pid);
  return phd;
}

typedef struct {
  void *   addr;
  uint32_t len;
} vent_t; /* VBA entry */

typedef struct {
  vent_t bios;
  vent_t cont;
  vent_t wram;
  vent_t iram;
  vent_t io;
  vent_t plt;
  vent_t vram;
  vent_t oam;
  vent_t rom;
} vdat_t; /* VBA data consist of VBA entries */

void
vshow(vdat_t * vba) {
  printf("vba bios    0x%08X len 0x%08X\n", vba->bios.addr, vba->bios.len);
  printf("vba const   0x%08X len 0x%08X\n", vba->cont.addr, vba->cont.len);
  printf("vba wram    0x%08X len 0x%08X\n", vba->wram.addr, vba->wram.len);
  printf("vba iram    0x%08X len 0x%08X\n", vba->iram.addr, vba->iram.len);
  printf("vba io      0x%08X len 0x%08X\n", vba->io.addr,   vba->io.len);
  printf("vba palette 0x%08X len 0x%08X\n", vba->plt.addr,  vba->plt.len);
  printf("vba vram    0x%08X len 0x%08X\n", vba->vram.addr, vba->vram.len);
  printf("vba oam     0x%08X len 0x%08X\n", vba->oam.addr,  vba->oam.len);
  printf("vba rom     0x%08X len 0x%08X\n", vba->rom.addr,  vba->rom.len);
}

#define VPTR ((void *) 0x00500000)
#define VLEN ((size_t) 0x00200000)

vdat_t
getvba(void * phd) {
  void * buf = malloc(VLEN);
  vdat_t ret = {0};
  vdat_t * vba;
  size_t i, read, total = 0;
  while (total < VLEN) {
    if (!ReadProcessMemory(phd, VPTR + total, buf + total, VLEN / 8,
                           (SIZE_T *) &read)) {
      printf("failed to read 0x%08X-0x%08X from process\n",
             VPTR + total, VPTR + total + read);
      free(buf);
      CloseHandle(phd);
      exit(1);
    }
    printf("read 0x%08X-0x%08X from process\n",
           VPTR + total, VPTR + total + read);
    total += read;
  }
  for (i = 0; i < VLEN - sizeof(vdat_t); i += sizeof(uint32_t)) {
    vba = buf + i;
    if (vba->bios.len    == 0x00003FFF &&
        vba->wram.len    == 0x0003FFFF &&
        vba->iram.len    == 0x00007FFF &&
        /* vba->io.len   == 0x000003FF &&  does not follow GBA spec */
        vba->plt.len     == 0x000003FF &&
        /* vba->vram.len == 0x0001FFFF &&  does not follow GBA spec */
        vba->oam.len     == 0x000003FF &&
        vba->rom.len     >= 0x01FFFFFF) {
      ret = * vba;
      break;
    }
  }
  free(buf);
  if (!ret.bios.len) {
    puts("valid VBA data not found");
    CloseHandle(phd);
    exit(1);
  }
  vshow(&ret);
  return ret;
}

void *
vtran(void * from, vdat_t * vba) {
  size_t index  = ((size_t) from & 0x0F000000) >> 24,
         offset = ((size_t) from & 0x00FFFFFF);
  void * to = index[(vent_t *) vba].addr + offset;
  printf("translate address 0x%08X to 0x%08X\n", from, to);
  return to;
}

void
vrecv(void * addr, void * buf, size_t len, vdat_t * vba, void * phd) {
  SIZE_T read;
  addr = vtran(addr, vba);
  if (!ReadProcessMemory(phd, addr, buf, len, &read) || read < len) {
    printf("read 0x%08X from process failed\n", addr);
    CloseHandle(phd);
    exit(1);
  }
  printf("read 0x%08X from process\n", addr);
}

void
vsend(void * addr, void * buf, size_t len, vdat_t * vba, void * phd) {
  SIZE_T wrote;
  addr = vtran(addr, vba);
  int ret = WriteProcessMemory(phd, addr, buf, len, &wrote);
  if (!ret || wrote < len) {
    printf("ret %d. write 0x%08X (len = %"PRIuPTR" from process failed\n",
           ret, addr, wrote);
    CloseHandle(phd);
    exit(1);
  }
  printf("write 0x%08X from process\n", addr);
}

#define MLEN 6

mon_t *
getmon(vref_t * ref, vdat_t * vba, void * phd) {
  size_t size = MLEN * sizeof(mon_t);
  mon_t * mon = malloc(size);
  vrecv(ref->e_jp.mon.addr, mon, size, vba, phd);
  return mon;
}

void
getmap(vdat_t * vba, void * phd) {
  uint32_t map = 0x0A00;
  while (1) {
    /*vsend((void *) 0x02031F84, &map, sizeof(map), vba, phd);*/
    vrecv((void *) 0x02031F84, &map, sizeof(map), vba, phd);
    printf("current map: 0x%08X\n", map);
    fflush(stdout);
    sleep(1);
  }
}

int
main(int argc, char ** argv) {
  vref_t * ref = getref();
  uint32_t pid = getpid(argc, argv);
  void *   phd = getphd(pid);
  vdat_t   vba = getvba(phd);
  mon_t *  mon = getmon(ref, &vba, phd);
  mdec(mon);
  mhexshow(mon);
  free(mon);
  getmap(&vba, phd);
  CloseHandle(phd);
  return 0;
}
