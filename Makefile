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

CPPFLAGS=$(DEPFLAGS) $(DEF) $(INCS)
CFLAGS=$(DBG) $(OPT) $(WARNINGS) $(STD)
LDFLAGS=$(LIBS)

INC_DIRS=. ./inc/ ./external/inc/
LIB_DIRS=./external/lib/
BUILD_DIR=build
CODE_DIRS=. src external/src
VPATH=$(CODE_DIRS)

SRC=$(foreach DIR,$(CODE_DIRS),$(wildcard $(DIR)/*.$(EXT)))

OBJ=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.o)))
DEP=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.d)))

PROJ=Main
EXEC=$(PROJ)

all: $(BUILD_DIR)/$(EXEC)
	@echo "========================================="
	@echo "              BUILD SUCCESS              "
	@echo "========================================="

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
$(BUILD_DIR)/$(EXEC): $(OBJ)
	$(CC) $^ -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@
	$(info SRC_DIRS  : $(CODE_DIRS))
	$(info INC_DIRS  : $(INC_DIRS))
	$(info INCS      : $(INCS))
	$(info SRC_FILES : $(SRC))
	$(info OBJ_FILES : $(OBJ))
	@echo "========================================="

clean:
	rm -fR $(BUILD_DIR)
graph:
	gprof $(BUILD_DIR)/$(EXEC) gmon.out | gprof2dot -w -s | dot -Tsvg -o output.svg
	gprof $(BUILD_DIR)/$(EXEC) gmon.out > analysis.txt

-include $(DEP)

.PHONY: all clean release debug graph profile
