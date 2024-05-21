CC=gcc
CFLAGS=-Wall -g
DEPS = file.h hptypes.h asmdefs.h asmencode.h asmdecode.h subroutine.h
OBJ = file.o hptypes.o asmdefs.o asmencode.o asmdecode.o subroutine.o

all: dump_object string_to_object code_to_object list_subroutines

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

dump_object: dump_object.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

string_to_object: string_to_object.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

code_to_object: code_to_object.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

list_subroutines: list_subroutines.o subroutine.o
	$(CC) -o $@ $^ $(CFLAGS)

clean :
	rm *.o
