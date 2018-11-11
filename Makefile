ROUTERD_TARG = routerd
EASYPING_TARG = easyping
ROUTERD_OBJ = routerd.o error.o coredata.o utils.o
EASYPING_OBJ = easyping.o error.o coredata.o utils.o
COMPILER = gcc
CFLAGS = -std=c99 -g -O2 -Wall

$(ROUTERD_TARG): $(ROUTERD_OBJ) $(EASYPING_TARG)
	$(COMPILER) $(CFLAGS) -o $(ROUTERD_TARG) $(ROUTERD_OBJ)

$(EASYPING_TARG): $(EASYPING_OBJ)
	$(COMPILER) $(CFLAGS) -o $(EASYPING_TARG) $(EASYPING_OBJ)

run: $(ROUTERD_TARG)
	sudo ./routerd

.PHONY: clean

clean:
	rm $(ROUTERD_TARG) $(EASYPING_TARG) *.o
