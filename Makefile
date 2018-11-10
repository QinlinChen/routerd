TARG = routerd
OBJ = routerd.o
COMPILER = gcc
CFLAGS = -g -O2 -Wall

TARG: $(OBJ)
	$(COMPILER) $(CFLAGS) -o $(TARG) $(OBJ)

run: TARG
	sudo ./routerd

.PHONY: clean cleanobj

clean: cleanobj
	rm $(TARG)

cleanobj:
	rm $(OBJ)