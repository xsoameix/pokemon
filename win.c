#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <signal.h>
#ifdef __WIN32__
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <netdb.h>
  #include <sys/socket.h>
#endif
#include <windows.h>
#include "lib.h"

typedef struct sockaddr         addr_t;
typedef struct sockaddr_storage addr_store_t;
typedef struct addrinfo         addr_info_t;

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
    /*printf("read 0x%08X-0x%08X from process\n",
           VPTR + total, VPTR + total + read);*/
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
  /*vshow(&ret);*/
  return ret;
}

void *
vtran(void * from, vdat_t * vba) {
  size_t index  = ((size_t) from & 0x0F000000) >> 24,
         offset = ((size_t) from & 0x00FFFFFF);
  void * to = index[(vent_t *) vba].addr + offset;
  /*printf("translate address 0x%08X to 0x%08X\n", from, to);*/
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
  /*printf("read 0x%08X from process\n", addr);*/
}

void
vsend(void * addr, void * buf, size_t len, vdat_t * vba, void * phd) {
  SIZE_T wrote;
  addr = vtran(addr, vba);
  if (!WriteProcessMemory(phd, addr, buf, len, &wrote) || wrote < len) {
    printf("write 0x%08X from process failed\n", addr);
    CloseHandle(phd);
    exit(1);
  }
  /*printf("write 0x%08X from process\n", addr);*/
}

#define MLEN 6
#define MSIZE (MLEN * sizeof(mon_t))

mon_t *
mrecv(vref_t * ref, vdat_t * vba, void * phd) {
  mon_t * mon = malloc(MSIZE);
  vrecv(ref->e_jp.mon.addr, mon, MSIZE, vba, phd);
  return mon;
}

void
msend(mon_t * mon, vref_t * ref, vdat_t * vba, void * phd) {
  vsend(ref->e_jp.mon.addr, mon, MSIZE, vba, phd);
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

void setintr(void);
void getintr(int signo);

void
setintr(void) {
  void (* sig)(int);
  sig = signal(SIGINT, getintr);
  if (sig == SIG_ERR) puts("cannot catch SIGINT"), fflush(stdout);
  sig = signal(SIGTERM, getintr);
  if (sig == SIG_ERR) puts("cannot catch SIGINT"), fflush(stdout);
}

int intr = 0;
int gsock;

void
getintr(int signo) {
  puts("bye");
  fflush(stdout);
  intr = 1;
#ifdef __WIN32__
  closesocket(gsock);
#else
  close(gsock);
#endif
  setintr();
}

addr_info_t *
getaddr(void) {
  addr_info_t hint = {0}, * res;
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_flags = AI_PASSIVE;
  getaddrinfo(NULL, "45000", &hint, &res);
  return res;
}

int
getsock(addr_info_t * addr) {
  int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (sock == -1) puts("socket failed"), exit(1);
  return sock;
}

int
setsock(void) {
  addr_info_t * addr = getaddr();
  int sock = getsock(addr), on = 1, ret;
  ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
  if (ret == -1) puts("setsockopt 'SO_REUSEADDR' failed"), exit(1);
  if (addr->ai_addr->sa_family == AF_INET6) {
    ret = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &on, sizeof(on));
    if (ret == -1) puts("setsockopt 'IPV6_V6ONLY' failed"), exit(1);
  }
  ret = bind(sock, addr->ai_addr, addr->ai_addrlen);
  if (ret == -1) puts("bind failed"), exit(1);
  ret = listen(sock, 20);
  if (ret == -1) puts("listen failed"), exit(1);
  freeaddrinfo(addr);
  return sock;
}

int
rcvsock(int new, void * buf, size_t len) {
  ssize_t ret = recv(new, buf, len, 0);
  if (ret == 0)   { puts("disconnect"),  fflush(stdout); return 1; }
  if (ret == -1)  { puts("recv failed"), fflush(stdout); return 1; }
  if (ret != len) { puts("recv error"),  fflush(stdout); return 1; }
  return 0;
}

void
sndsock(int new, void * buf, size_t len) {
  ssize_t ret = send(new, buf, len, 0);
  if (ret == -1)  puts("send failed"), fflush(stdout);
  if (ret != len) puts("send failed"), fflush(stdout);
}

#define EXEQUIT  0
#define EXEMONLV 1
#define EXEMONPP 2

void
exesock(int new, vdat_t * vba, void * phd, vref_t * ref) {
  mon_t * mon;
  uint8_t cmd;
  while (!rcvsock(new, &cmd, sizeof(cmd))) {
    if (cmd == EXEQUIT) {
      puts("disconnect"), fflush(stdout); break;
    }
    if (mdec(mon = mrecv(ref, vba, phd))) {
      puts("not valid mon_t"), fflush(stdout), free(mon); break;
    }
    if (cmd == EXEMONLV)
      sndsock(new, &mon->lv, sizeof(mon->lv));
    if (cmd == EXEMONPP) {
      mon->dat.a.pp[0] = 5;
      sndsock(new, mon->dat.a.pp, sizeof(* mon->dat.a.pp));
      menc(mon), msend(mon, ref, vba, phd);
    }
    free(mon);
  }
}

void
accsock(vdat_t * vba, void * phd, vref_t * ref) {
  socklen_t addrlen;
  addr_store_t addr;
  int sock, new;
#ifdef __WIN32__
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa))
    puts("WSAStartup failed"), fflush(stdout), exit(0);
#endif
  sock = gsock = setsock();
  while (!intr) {
    addrlen = sizeof(addr);
    memset(&addr, 0, addrlen);
    new = accept(sock, (addr_t *) &addr, &addrlen);
    if (new == -1 && !intr) puts("accept failed"), fflush(stdout);
    if (new == -1) continue;
    exesock(new, vba, phd, ref);
    close(new);
  }
#ifdef __WIN32__
  WSACleanup();
#endif
}

int
main(int argc, char ** argv) {
  vref_t * ref = getref();
  uint32_t pid = getpid(argc, argv);
  void *   phd = getphd(pid);
  vdat_t   vba = getvba(phd);
  setintr();
  accsock(&vba, phd, ref);
  CloseHandle(phd);
  return 0;
}
