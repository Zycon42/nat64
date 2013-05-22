# Projekt do predmetu ISA/2011
# autor: Jan Dušek
#

NAME=nat64
CXX=g++
CXXFLAGS=-std=c++98 -Wall -pedantic -g
LDFLAGS=-lpcap -lnet
OBJFILES=main.o nattable.o nat.o sniffer.o snifferservice.o log.o packets.o checksum.o sender.o

.PHONY: all clean depend

all: $(NAME)

-include dep.list

$(NAME): $(OBJFILES)
	$(CXX) $(LDFLAGS) -o $(NAME) $(OBJFILES)

depend:
	$(CXX) -MM *.cpp > dep.list

clean:
	rm -f *.o $(NAME)