CC=gcc
#INC=$/home/dascoisas/Desktop/ed25519 $/home/dascoisas/Desktop/ed25519/src
#INC_PARAMS=$(foreach d, $(INC), -I$d)
OBJ=teste
SRC=$(wildcard *.c)

$(OBJ): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	
all: $(OBJ)

clean:
	rm $(OBJ)
