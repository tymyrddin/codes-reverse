CXX=g++
OBJ=loader_test

.PHONY: all clean

all: $(OBJ)

loader.o: loader.cc
	$(CXX) -std=c++11 -c loader.cc

loader_test: loader.o loader_test.cc
	$(CXX) -std=c++11 -o loader_test loader_test.cc loader.o -lbfd

clean:
	rm -f $(OBJ) *.o

