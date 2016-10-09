CC= gcc
CFLAGS= -g
LIBOBJS = myalloc.o
LIB=myalloc
LIBFILE=lib$(LIB).a
TESTS = test1 test2 test3 test4 test5 test6 test7 test8
all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

test% : test%.o $(LIB)
	$(CC) test$*.o $(CFLAGS) -o test$* -L. -l$(LIB)

$(LIB) : $(LIBOBJS)
	ar -cvr $(LIBFILE) $(LIBOBJS)
	#ranlib $(LIBFILE) # may be needed on some systems
	ar -t $(LIBFILE)

clean:
	/bin/rm -f *.o $(TESTS) $(LIBFILE)
