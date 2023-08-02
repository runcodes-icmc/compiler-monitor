CFLAGS = -Wall -O2 -static

all: monitor.o monitor

monitor.o: monitor.c
	gcc $(CFLAGS) -c monitor.c -o monitor.o

monitor: main.c monitor.o
	gcc $(CFLAGS) main.c monitor.o -o monitor

clean:
	rm -f monitor.o monitor

.PHONY: clean
