.PHONY: all debug release clean

RELEASE_FLAGS = -O2 -Wall -DNDEBUG 
DEBUG_FLAGS   = -g -O0 -Wall
RELEASE_EXEC  = Hash
DEBUG_EXEC    = Hash-dbg
SOURCE        = main.cpp

all: debug release

debug: $(DEBUG_EXEC)

$(DEBUG_EXEC): $(SOURCE)
	g++ $(DEBUG_FLAGS) $(SOURCE) -o $(DEBUG_EXEC) -lcrypto++

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(SOURCE)
	g++ $(RELEASE_FLAGS) $(SOURCE) -o $(RELEASE_EXEC) -lcrypto++

clean:
	rm -f $(RELEASE_EXEC) $(DEBUG_EXEC)
