CC       = g++
CFLAGS   = -std=c++17 -O2 -Wall -Wextra
LDFLAGS  = -lcurl -lpthread
TARGET   = c2client
SRC      = main.cpp

# Override at build time:  make C2_SERVER=10.0.0.1:8000 C2_INTERVAL=10
C2_SERVER   ?=
C2_INTERVAL ?=
C2_JITTER   ?=

ifneq ($(C2_SERVER),)
  CFLAGS += -DC2_DEFAULT_SERVER='"$(C2_SERVER)"'
endif
ifneq ($(C2_INTERVAL),)
  CFLAGS += -DC2_DEFAULT_INTERVAL=$(C2_INTERVAL)
endif
ifneq ($(C2_JITTER),)
  CFLAGS += -DC2_DEFAULT_JITTER=$(C2_JITTER)
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	strip $@

debug: $(SRC)
	$(CC) -std=c++17 -g -O0 -Wall -Wextra -o $(TARGET)_dbg $< $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET)_dbg
