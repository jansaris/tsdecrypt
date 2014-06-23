##### compiling with g++ gives a little more speed
COMPILER=gcc
#COMPILER=g++


#FLAGS += -g
#FLAGS += -fno-alias
#FLAGS += -vec_report3
#FLAGS += -Wall -Winline
#FLAGS += -fomit-frame-pointer 
#FLAGS += -pg

COMPILER ?= g++
FLAGS    ?= -Wall -fPIC -fomit-frame-pointer -fexpensive-optimizations -funroll-loops

H_FILES = libaesdec.h 

all: libaesdec.o

%.o: %.c
	$(COMPILER) $(FLAGS) -c $<


libaesdec.o: 	libaesdec.c $(H_FILES)

clean:
	@rm -f libaesdec.o

