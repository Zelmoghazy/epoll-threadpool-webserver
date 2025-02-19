CC=g++
EXT=cpp

OPT=
DBG=
WARNINGS=-Wall -Wextra -Wsign-conversion -Wconversion
STD=-std=c++17
DEPFLAGS=-MP -MD

INCS=$(foreach DIR,$(INC_DIRS),-I$(DIR))
LIBS=$(foreach DIR,$(LIB_DIRS),-L$(DIR))
LIBS+=-l:libsqlite3.a

CFLAGS=$(DBG) $(OPT) $(INCS) $(LIBS) $(WARNINGS) $(DEPFLAGS) $(STD)

INC_DIRS=. ./inc/ ./external/inc/
LIB_DIRS=./external/lib/
BUILD_DIR=build
CODE_DIRS=. src external/src
VPATH=$(CODE_DIRS)

SRC=$(foreach DIR,$(CODE_DIRS),$(wildcard $(DIR)/*.$(EXT)))

OBJ=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.o)))
DEP=$(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.d)))

EXEC=Main

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
#profile: CFLAGS += -fno-inline-functions -fno-inline-functions-called-once -fno-optimize-sibling-calls -fno-default-inline -fno-inline 
profile: all

$(BUILD_DIR)/%.o: %.$(EXT) | $(BUILD_DIR)
	$(CC) -c  $< -o $@ $(CFLAGS)
$(BUILD_DIR)/$(EXEC): $(OBJ)
	$(CC)  $^ -o $@ $(CFLAGS)

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
	gprof ./build/Main gmon.out | gprof2dot -w -s | dot -Tsvg -o output.svg
	gprof ./build/Main gmon.out > analysis.txt

-include $(DEP)

.PHONY: all clean release debug
