default: ssh-trap

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -flto -fuse-linker-plugin
LDFLAGS += -lssh -lpthread -march=native -Ofast -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

all: ssh-trap

ssh-trap: $(OBJS)
	$(CC) $(OBJS) -o ssh-trap $(LDFLAGS)

OBJS: $(SRCS)
	$(CC) $(CFLAGS) -c -o $@ $(SRCS)

clean:
	$(RM) ssh-trap src/*.o
