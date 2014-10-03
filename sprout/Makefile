# Top level makefile for the sprout SIP router

.PHONY: all
all:
	make -f sprout_base.mk
	make -f sprout_scscf.mk
	make -f sprout_icscf.mk
	make -f sprout_bgcf.mk
	make -f sprout_mmtel_as.mk
	make -f gemini_as.mk
	make -f memento_as.mk

.PHONY: test run_test coverage coverage-check coverage_raw debug vg vg-check vg_raw
test run_test coverage coverage-check coverage_raw debug vg vg-check vg_raw:
	make -f sprout_test.mk $@

.PHONY: clean
clean:
	make -f sprout_base.mk clean
	make -f sprout_scscf.mk clean
	make -f sprout_icscf.mk clean
	make -f sprout_bgcf.mk clean
	make -f sprout_mmtel_as.mk clean
	make -f gemini_as.mk clean
	make -f memento_as.mk clean
	make -f sprout_test.mk clean
