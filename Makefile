CXX=g++
CXXFLAGS=-Wall -std=c++11 -O2 -DNDEBUG
LDFLAGS=-lcapstone -lbfd

SRC=nucleus.cc bb.cc cfg.cc dataregion.cc disasm.cc edge.cc exception.cc export.cc function.cc insn.cc loader.cc log.cc options.cc strategy.cc util.cc
OBJ=$(patsubst %.cc,obj/%.o,$(SRC))
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

setup:
	sudo apt install binutils-multiarch-dev libcapstone-dev
