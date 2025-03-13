CC=g++
EXT=cpp

OPT=
DBG=
WARNINGS=-Wall -Wextra -Wsign-conversion -Wconversion
STD=-std=c++17
DEPFLAGS=-MP -MD
DEF=

INCS=$(foreach DIR,$(INC_DIRS),-I$(DIR))
LIBS=$(foreach DIR,$(LIB_DIRS),-L$(DIR))
LIBS+=-l:libsqlite3.a

TEST_LIBS=$(LIBS)
TEST_LIBS+=-lcatch

CPPFLAGS=$(DEPFLAGS) $(DEF) $(INCS)
CFLAGS=$(DBG) $(OPT) $(WARNINGS) $(STD)
LDFLAGS=$(LIBS)

TEST_LDFLAGS=$(TEST_LIBS)

INC_DIRS=. ./inc/ ./external/inc/
LIB_DIRS=./external/lib/
BUILD_DIR=build
CODE_DIRS=. src external/src

TEST_BUILD_DIR=$(BUILD_DIR)/test
TEST_DIRS=tests

VPATH=$(CODE_DIRS) $(TEST_DIRS)

SRC=$(foreach DIR,$(CODE_DIRS),$(wildcard $(DIR)/*.$(EXT)))

TEST_SRC=$(foreach DIR,$(TEST_DIRS),$(wildcard $(DIR)/*.$(EXT)))

MAIN_SRC=$(filter %/$(EXEC).$(EXT), $(SRC))
SRC_NO_MAIN=$(filter-out %/$(EXEC).$(EXT), $(SRC))

OBJ=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.o)))
OBJ_NO_MAIN=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC_NO_MAIN:.$(EXT)=.o)))
TEST_OBJ=$(addprefix $(TEST_BUILD_DIR)/,$(notdir $(TEST_SRC:.$(EXT)=.o)))

DEP=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.d)))
TEST_DEP=$(addprefix $(TEST_BUILD_DIR)/,$(notdir $(TEST_SRC:.$(EXT)=.d)))

PROJ=Main
EXEC=$(PROJ)
TEST_EXEC=test

all: $(BUILD_DIR)/$(EXEC)
	@echo "========================================="
	@echo "              BUILD SUCCESS              "
	@echo "========================================="

test: $(TEST_BUILD_DIR)/$(TEST_EXEC)
	@echo "========================================="
	@echo "            TEST BUILD SUCCESS           "
	@echo "========================================="
	./$(TEST_BUILD_DIR)/$(TEST_EXEC)

release: OPT += -O2
release: all

debug: DBG += -g -gdwarf-2 -fsanitize=address
debug: OPT += -O0
debug: all

profile: DBG += -g -gdwarf-2
profile: OPT += -O2
profile: CFLAGS += -DNDEBUG -pg
profile: CFLAGS += -fno-inline-functions -fno-inline-functions-called-once -fno-optimize-sibling-calls -fno-default-inline -fno-inline 
profile: all

$(BUILD_DIR)/%.o: %.$(EXT) | $(BUILD_DIR)
	$(CC) -c  $< -o $@ $(CPPFLAGS) $(CFLAGS)

$(TEST_BUILD_DIR)/%.o: %.$(EXT) | $(TEST_BUILD_DIR)
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)

$(BUILD_DIR)/$(EXEC): $(OBJ)
	$(CC) $^ -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

$(TEST_BUILD_DIR)/$(TEST_EXEC): $(OBJ_NO_MAIN) $(TEST_OBJ)
	$(CC) $^ -o $@ $(CPPFLAGS) $(CFLAGS) $(TEST_LDFLAGS)

$(BUILD_DIR):
	mkdir $@
	$(info SRC_DIRS  : $(CODE_DIRS))
	$(info INC_DIRS  : $(INC_DIRS))
	$(info INCS      : $(INCS))
	$(info SRC_FILES : $(SRC))
	$(info OBJ_FILES : $(OBJ))
	@echo "========================================="

$(TEST_BUILD_DIR):
	mkdir -p $@
	$(info TEST_DIRS : $(TEST_DIRS))
	$(info TEST_SRC  : $(TEST_SRC))
	$(info TEST_OBJ  : $(TEST_OBJ))
	@echo "========================================="

clean:
	rm -fR $(BUILD_DIR)
graph:
	gprof $(BUILD_DIR)/$(EXEC) $(BUILD_DIR)/gmon.out | gprof2dot -w -s | dot -Tsvg -o $(BUILD_DIR)/output.svg
	gprof $(BUILD_DIR)/$(EXEC) $(BUILD_DIR)/gmon.out > $(BUILD_DIR)/analysis.txt

-include $(DEP)
-include $(TEST_DEP)

.PHONY: all clean release debug graph profile test
