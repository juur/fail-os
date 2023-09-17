#ifndef _IOCTLS_H
#define _IOCTLS_H

#define TCGETS  0x5401
#define TCSETS  0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

#define TIOCNOTTY  0x5422

#define VEOF     0
#define VEOL     1
#define VERASE   2
#define VINTR    3
#define VKILL    4
#define VMIN     5
#define VQUIT    6
#define VSTART   7
#define VSTOP    8
#define VSUSP    9
#define VTIME   10

/* mirror Linux */
#define NCCS    32

#define BRKINT  00001
#define ICRNL   00002
#define IGNBRK  00004
#define IGNCR   00010
#define IGNPAR  00020
#define INLCR   00040
#define INPCK   00100
#define ISTRIP  00200
#define IXANY   00400
#define IXOFF   01000
#define IXON    02000
#define PARMRK  04000

#define OPOST   000000001
#define ONLCR   000000002
#define OCRNL   000000004
#define ONOCR   000000010
#define ONLRET  000000020
#define OFDEL   000000040
#define OFILL   000000100
#define NL0     000000200
#define NL1     000000400
#define CR0     000001000
#define CR1     000002000
#define CR2     000004000
#define CR3     000010000
#define TAB0    000020000
#define TAB1    000040000
#define TAB2    000100000
#define TAB3    000200000
#define BS0     000400000
#define BS1     001000000
#define VT0     002000000
#define VT1     004000000
#define FF0     010000000
#define FF1     020000000

#define B0      0
#define B50     50
#define B75     75
#define B110    110
#define B134    134
#define B150    150
#define B200    200
#define B300    300
#define B600    600
#define B1200   1200
#define B1800   1800
#define B2400   2400
#define B4800   4800
#define B9600   9600
#define B19200  19200
#define B38400  38400

#define CS5     0001
#define CS6     0002
#define CS7     0003
#define CS8     0004
#define CSTOPB  0010
#define CREAD   0020
#define PARENB  0040
#define PARODD  0100
#define HUPCL   0200
#define CLOCAL  0400

#define ECHO    0001
#define ECHOE   0002
#define ECHOK   0004
#define ECHONL  0010
#define ICANON  0020
#define IEXTEN  0040
#define ISIG    0100
#define NOFLSH  0200
#define TOSTOP  0400

#define TCSANOW   1
#define TCSADRAIN 2
#define TCSAFLUSH 3

#define TCIFLUSH  1
#define TCOFLUSH  2
#define TCIOFLUSH 3

#define TCIOFF 1
#define TCION  2
#define TCOOFF 3
#define TCOON  4

#define CSIZE   CS8
#define CRDLY   CR0
#define TABDLY  TAB3
#define BSDLY   BS0
#define VTDLY   VT0
#define FFDLY   FF0
#define NLDLY   NL0

/* TODO NL0/CR0/TAB0/BS0/VT0/FF0 */

typedef int cc_t;
typedef int speed_t;
typedef unsigned int tcflag_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;

    cc_t c_line;
    cc_t c_cc[NCCS];

    speed_t c_ispeed;
    speed_t c_ospeed;
};

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel, ws_ypixel;
};

#endif
