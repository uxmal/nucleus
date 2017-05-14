CXX=g++
CXXFLAGS=-Wall -std=c++11 -O2 -DNDEBUG
LDFLAGS=-lcapstone -lbfd

SRC=$(wildcard *.cc)
OBJ=$(patsubst %.cc, obj/%.o, $(SRC))
BIN=nucleus

.PHONY: all clean

all: $(BIN)

$(OBJ): | obj

obj:
	@mkdir -p $@

obj/%.o: %.cc %.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ)
	rm -Rf obj
	rm -f $(BIN)

