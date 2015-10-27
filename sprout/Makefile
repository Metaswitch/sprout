# Top level Makefile for the sprout SIP router

.PHONY: all
all:
	${MAKE} -f sprout_base.mk
	${MAKE} -f sprout_scscf.mk
	${MAKE} -f sprout_icscf.mk
	${MAKE} -f sprout_bgcf.mk
	${MAKE} -f sprout_mmtel_as.mk
	${MAKE} -f gemini_as.mk
	${MAKE} -f memento_as.mk
	${MAKE} -f cdiv_as.mk
	${MAKE} -f mangelwurzel/mangelwurzel_as.mk
	find  ../plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} \;

.PHONY: test run_test coverage coverage-check coverage_raw debug vg vg-check vg_raw
test run_test coverage coverage-check coverage_raw debug vg vg-check vg_raw:
	${MAKE} -f sprout_test.mk $@
	find  ../plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} $@ \;

.PHONY: clean
clean:
	${MAKE} -f sprout_base.mk clean
	${MAKE} -f sprout_scscf.mk clean
	${MAKE} -f sprout_icscf.mk clean
	${MAKE} -f sprout_bgcf.mk clean
	${MAKE} -f sprout_mmtel_as.mk clean
	${MAKE} -f gemini_as.mk clean
	${MAKE} -f memento_as.mk clean
	${MAKE} -f cdiv_as.mk clean
	${MAKE} -f mangelwurzel/mangelwurzel_as.mk clean
	${MAKE} -f sprout_test.mk clean
	find  ../plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} clean \;
