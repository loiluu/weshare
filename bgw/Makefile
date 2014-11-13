top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
libdir = -L ${exec_prefix}/lib
INCLUDE = -I ${prefix}/include/pbc

LDFLAGS = -lgmp -lpbc -lm
CC = gcc
CFLAGS =  -O3 -Wunused-result
SOURCES= testbce.c bce.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE= testbce


all : $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	      $(CC)  $(CFlAGS) $(INCLUDES) -o $@ $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC)  $(CFlAGS)  $(INCLUDE) $(libdir) $(LDFLAGS) -c $< -o $@


clean :
	 $(RM) *~  *.o testbce bce 






