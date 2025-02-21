CC = clang
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -framework IOKit -framework CoreFoundation

TARGET = main
SRC = main.c

ENTITLEMENTS = ./ent.plist

all: $(TARGET) sign

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

sign: $(TARGET)
	codesign -s - --entitlements $(ENTITLEMENTS) -f $(TARGET)
	@echo "[*] Code signing completed."

clean:
	rm -f $(TARGET)

.PHONY: all sign clean
