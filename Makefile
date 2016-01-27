
CFLAGS := -O2 -Wall -DNDEBUG	\
	  -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D_GNU_SOURCE -std=c99

OBJ :=  fat_fuse.o		\
	fat_file.o		\
	fat_fuse_ops.o		\
	fat_util.o		\
	fat_volume.o		\
	avl_tree.o

LDLIBS  := -lfuse
HEADERS := $(wildcard *.h)
EXE     := fat-fuse

$(EXE):$(OBJ)
	$(CC) -o$@ $(LDFLAGS) $(OBJ) $(LDLIBS) 

$(OBJ):$(HEADERS)

clean:
	rm -f $(EXE) $(OBJ) tags cscope*

.PHONY: clean
