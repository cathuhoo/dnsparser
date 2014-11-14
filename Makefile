## Makefile for dns-parser ##

CFLAGS=-c -Wall -g -O0 -DDEBUG

CC=gcc
LDFLAGS=-lresolv -lpthread -lm -lpcap
SOURCES= dns-parser.c inX_addr.c list.c trie.c  mystring.c


OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=parser

prefix=/usr/local/$(EXECUTABLE)

all: $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) -o $@ $(OBJECTS)  $(LDFLAGS)

%.o: %.c *.h 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS) 
	rm -f $(EXECUTABLE) 
    
install:
	cp  $(EXECUTABLE) $(prefix)
