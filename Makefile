CC=gcc 
LDFLAGS= -lpcap  
CFLAGS= -Wall -g
SOURCE= dns-sniffer.c
OBJS=$(SOURCE:.cc=.o)
TARGET= dns-sniffer

.c.o:
	$(CC) $(CFLAGS) $< -o $@

all: release

release: $(OBJS)
	$(CC)  -o $(TARGET) $^ $(LDFLAGS)

x:
	./dns-sniffer -i eth0

debug: 
	jdebug=true ./dns-sniffer -i eth0

clean:
	rm -f  *.o  $(TARGET)

