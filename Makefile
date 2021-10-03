CC = gcc
CPPFLAGS := -Iinclude -MMD -MP # (C) (P)re(P)rocessor not c++, -MMD -MP are used to generated header depends automatically
CFLAGS := -Wall -O2
LDFLAGS := -Llib
LDLIBS := -lm

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

PROJECT := cryptomath

EXE := $(BIN_DIR)/$(PROJECT)
SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

run:
	$(EXE) $(ARGS)

-include $(OBJ:.o=.d)
