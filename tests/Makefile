# tests Makefile

SUBDIRS := curl1 curl3 curl4

all:
	$(foreach dir,${SUBDIRS}, make -C ${dir} $@; )

test:
	$(foreach dir,${SUBDIRS}, make -C ${dir} $@; )

clean:
	$(foreach dir,${SUBDIRS}, make -C ${dir} $@; )

distclean:
	$(foreach dir,${SUBDIRS}, make -C ${dir} $@; )

.PHONY: all test clean distclean
