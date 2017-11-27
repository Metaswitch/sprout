TARGETS := sprout call-diversion-as.so gemini-as.so memento-as.so sprout_bgcf.so sprout_icscf.so sprout_mmtel_as.so sprout_scscf.so mangelwurzel-as.so

TEST_TARGETS := sprout_test

SPROUT_COMMON_SOURCES := logger.cpp \
                         saslogger.cpp \
                         utils.cpp \
                         analyticslogger.cpp \
                         stack.cpp \
                         dnsparser.cpp \
                         dnscachedresolver.cpp \
                         baseresolver.cpp \
                         sipresolver.cpp \
                         bono.cpp \
                         registration_utils.cpp \
                         hss_sip_mapping.cpp \
                         options.cpp \
                         sip_connection_pool.cpp \
                         flowtable.cpp \
                         http_connection_pool.cpp \
                         httpclient.cpp \
                         httpconnection.cpp \
                         a_record_resolver.cpp \
                         hssconnection.cpp \
                         websockets.cpp \
                         localstore.cpp \
                         memcached_connection_pool.cpp \
                         memcachedstore.cpp \
                         memcachedstoreview.cpp \
                         memcached_config.cpp \
                         impistore.cpp \
                         astaire_impistore.cpp \
                         subscriber_data_manager.cpp \
                         xdmconnection.cpp \
                         simservs.cpp \
                         enumservice.cpp \
                         bgcfservice.cpp \
                         icscfrouter.cpp \
                         scscfselector.cpp \
                         dnsresolver.cpp \
                         log.cpp \
                         pjutils.cpp \
                         statistic.cpp \
                         zmq_lvc.cpp \
                         trustboundary.cpp \
                         sessioncase.cpp \
                         ifchandler.cpp \
                         aschain.cpp \
                         custom_headers.cpp \
                         accumulator.cpp \
                         connection_tracker.cpp \
                         quiescing_manager.cpp \
                         dialog_tracker.cpp \
                         load_monitor.cpp \
                         counter.cpp \
                         basicproxy.cpp \
                         acr.cpp \
                         signalhandler.cpp \
                         health_checker.cpp \
                         notify_utils.cpp \
                         unique.cpp \
                         chronosconnection.cpp \
                         accesslogger.cpp \
                         httpstack.cpp \
                         httpstack_utils.cpp \
                         handlers.cpp \
                         chronoshandlers.cpp \
                         contact_filtering.cpp \
                         sproutletproxy.cpp \
                         compositesproutlet.cpp \
                         pluginloader.cpp \
                         alarm.cpp \
                         base_communication_monitor.cpp \
                         communicationmonitor.cpp \
                         thread_dispatcher.cpp \
                         common_sip_processing.cpp \
                         exception_handler.cpp \
                         snmp_agent.cpp \
                         snmp_continuous_accumulator_table.cpp \
                         snmp_continuous_accumulator_by_scope_table.cpp \
                         sip_string_to_request_type.cpp \
                         snmp_row.cpp \
                         snmp_ip_row.cpp \
                         snmp_scalar.cpp \
                         ralf_processor.cpp \
                         uri_classifier.cpp \
                         namespace_hop.cpp \
                         session_expires_helper.cpp \
                         base64.cpp \
                         as_communication_tracker.cpp \
                         astaire_resolver.cpp \
                         xml_utils.cpp \
                         wildcard_utils.cpp \
                         ifc.cpp \
                         associated_uris.cpp \
                         sifcservice.cpp \
                         fifcservice.cpp \
                         event_statistic_accumulator.cpp \
                         aor.cpp \
                         astaire_aor_store.cpp \
                         sprout_xml_utils.cpp \
                         rphservice.cpp

sprout_SOURCES := ${SPROUT_COMMON_SOURCES} \
                  snmp_counter_table.cpp \
                  snmp_counter_by_scope_table.cpp \
                  snmp_ip_count_table.cpp \
                  snmp_success_fail_count_table.cpp \
                  snmp_success_fail_count_by_request_type_table.cpp \
                  snmp_success_fail_count_by_priority_and_scope_table.cpp \
                  snmp_event_accumulator_table.cpp \
                  snmp_event_accumulator_by_scope_table.cpp \
                  snmp_scalar_by_scope_table.cpp \
                  main.cpp

sprout_test_SOURCES := ${SPROUT_COMMON_SOURCES} \
                       mangelwurzel.cpp \
                       mobiletwinned.cpp \
                       scscfsproutlet.cpp \
                       icscfsproutlet.cpp \
                       bgcfsproutlet.cpp \
                       subscriptionsproutlet.cpp \
                       registrarsproutlet.cpp \
                       sproutletappserver.cpp \
                       mmtel.cpp \
                       test_main.cpp \
                       fakecurl.cpp \
                       fakehttpconnection.cpp \
                       fakexdmconnection.cpp \
                       fakehssconnection.cpp \
                       fakelogger.cpp \
                       faketransport_udp.cpp \
                       faketransport_tcp.cpp \
                       fakednsresolver.cpp \
                       fakechronosconnection.cpp \
                       basetest.cpp \
                       siptest.cpp \
                       sip_common.cpp \
                       sipresolver_test.cpp \
                       authentication_test.cpp \
                       simservs_test.cpp \
                       hssconnection_test.cpp \
                       xdmconnection_test.cpp \
                       enumservice_test.cpp \
                       subscriber_data_manager_test.cpp \
                       astaire_impistore_test.cpp \
                       registrar_test.cpp \
                       bono_test.cpp \
                       bgcfservice_test.cpp \
                       options_test.cpp \
                       aschain_test.cpp \
                       sessioncase_test.cpp \
                       ifchandler_test.cpp \
                       sip_parser_test.cpp \
                       connection_tracker_test.cpp \
                       quiescing_manager_test.cpp \
                       dialog_tracker_test.cpp \
                       flow_test.cpp \
                       icscfsproutlet_test.cpp \
                       basicproxy_test.cpp \
                       scscfselector_test.cpp \
                       acr_test.cpp \
                       subscription_test.cpp \
                       handlers_test.cpp \
                       chronoshandlers_test.cpp \
                       mock_sas.cpp \
                       contact_filtering_test.cpp \
                       appserver_test.cpp \
                       scscf_test.cpp \
                       sproutletproxy_test.cpp \
                       gruu_test.cpp \
                       mobiletwinned_test.cpp \
                       mangelwurzel_test.cpp \
                       common_sip_processing_test.cpp \
                       fakesnmp.cpp \
                       fakezmq.cpp \
                       uriclassifier_test.cpp \
                       ralf_processor_test.cpp \
                       mockhttpconnection.cpp \
                       mockhttpstack.cpp \
                       mocktsxhelper.cpp \
                       mock_hss_connection.cpp \
                       mock_analytics_logger.cpp \
                       mock_sproutlet.cpp \
                       session_expires_helper_test.cpp \
                       mock_subscriber_data_manager.cpp \
                       mock_chronos_connection.cpp \
                       cassandra_connection_pool.cpp \
                       cassandra_store.cpp \
                       call_list_store.cpp \
                       mementosaslogger.cpp \
                       call_list_store_processor.cpp \
                       httpnotifier.cpp \
                       mockhttpnotifier.cpp \
                       mementoappserver.cpp \
                       call_list_store_processor_test.cpp \
                       mementoappserver_test.cpp \
                       httpnotifier_test.cpp \
                       bgcf_test.cpp \
                       as_communication_tracker_test.cpp \
                       authenticationsproutlet.cpp \
                       pthread_cond_var_helper.cpp \
                       sifcservice_test.cpp \
                       mock_sifc_parser.cpp \
                       fifcservice_test.cpp \
                       scscf_utils.cpp \
                       test_interposer.cpp \
                       curl_interposer.cpp \
                       testingcommon.cpp \
                       thread_dispatcher_test.cpp \
                       rphservice_test.cpp \
                       mock_rph_service.cpp

COVERAGE_ROOT := ..
sprout_test_COVERAGE_EXCLUSIONS := ^src/ut|^usr|^modules/gmock|^modules/cpp-common|^modules/rapidjson|^include|^src/mangelwurzel/ut|^modules/gemini/src/ut|^modules/gemini/include|^modules/memento-as/modules|^modules/memento-as/src/ut|^modules/memento-as/include

SPROUT_COMMON_CPPFLAGS := -Wno-write-strings \
                          -I../include \
                          -I../modules/cpp-common/include \
                          -I../modules/app-servers/include \
                          -I../usr/include \
                          -I../modules/rapidjson/include \
                          `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --cflags libpjproject`

sprout_CPPFLAGS := ${SPROUT_COMMON_CPPFLAGS}
sprout_test_CPPFLAGS := ${SPROUT_COMMON_CPPFLAGS} \
                        -I../modules/sipp \
                        -I../modules/app-servers/test \
                        -I../modules/memento-as/include \
                        -I../modules/memento-as/modules/memento-common/include \
                        -I../modules/gemini/include \
                        -I../include/mangelwurzel \
                        -Iut \
                        -DGTEST_USE_OWN_TR1_TUPLE=0

SPROUT_COMMON_LDFLAGS := -rdynamic \
                         -Wl,-rpath -Wl,/usr/share/clearwater/sprout/lib \
                         -L../usr/lib \
                         -lmemcached \
                         -lmemcachedutil \
                         -lssl \
                         -lcrypto \
                         -ldl \
                         -lwebsocketpp \
                         -lboost_regex \
                         -lboost_system \
                         -lboost_thread \
                         -lcares \
                         -lzmq \
                         -levhtp \
                         -levent \
                         -levent_pthreads \
                         -lcurl \
                         -lsas \
                         -lz \
                         -lpthread \
                         -lboost_filesystem \
                         `net-snmp-config --netsnmp-agent-libs`

# Explicitly link some pjsip modules. Some plugins require symbols in them
# (which sprout-base doesn't), and the plugins are dynamically linked at run
# time, so GCC won't link in the symbols they need unless we explicitly tell
# it to.
#
# The PJSIP bits must be first as the flags generated by pkg-config are
# misordered and we fix this by re-specifying certain SSL dependencies in
# SPROUT_COMMON_LDFLAGS.
sprout_LDFLAGS := -Wl,--whole-archive -lpjsip-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -Wl,--no-whole-archive `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --libs libpjproject` ${SPROUT_COMMON_LDFLAGS}
sprout_test_LDFLAGS := ${SPROUT_COMMON_LDFLAGS} \
                       -lthrift \
                       -lcassandra \
                       -lboost_date_time \
                       `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --libs libpjproject`

# Build rules for sproutlet plugins
PLUGIN_COMMON_CPPFLAGS := -fPIC \
                          -I../include \
                          -I../modules/cpp-common/include \
                          -I../modules/app-servers/include \
                          -I../modules/rapidjson/include \
                          `PKG_CONFIG_PATH=../usr/lib/pkgconfig pkg-config --cflags libpjproject`
PLUGIN_COMMON_LDFLAGS := -shared -L../usr/lib

gemini-as.so_SOURCES := mobiletwinned.cpp sproutletappserver.cpp geminiasplugin.cpp
gemini-as.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS} -I../modules/gemini/include
gemini-as.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

memento-as.so_SOURCES := sproutletappserver.cpp mementoasplugin.cpp cassandra_store.cpp cassandra_connection_pool.cpp call_list_store.cpp mementosaslogger.cpp call_list_store_processor.cpp httpnotifier.cpp mementoappserver.cpp
memento-as.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS} -I../modules/memento-as/include -I../modules/memento-as/modules/memento-common/include
memento-as.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS} -lthrift -lcassandra

call-diversion-as.so_SOURCES := mmtel.cpp sproutletappserver.cpp cdivasplugin.cpp
call-diversion-as.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS} -Wno-write-strings
call-diversion-as.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

sprout_bgcf.so_SOURCES := bgcfsproutlet.cpp bgcfservice.cpp bgcfplugin.cpp
sprout_bgcf.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS}
sprout_bgcf.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

sprout_icscf.so_SOURCES := icscfsproutlet.cpp icscfrouter.cpp scscfselector.cpp icscfplugin.cpp
sprout_icscf.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS}
sprout_icscf.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

sprout_mmtel_as.so_SOURCES := mmtel.cpp sproutletappserver.cpp mmtelasplugin.cpp
sprout_mmtel_as.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS} -Wno-write-strings
sprout_mmtel_as.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

sprout_scscf.so_SOURCES := authenticationsproutlet.cpp registrarsproutlet.cpp subscriptionsproutlet.cpp scscfsproutlet.cpp scscfplugin.cpp scscf_utils.cpp
sprout_scscf.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS}
sprout_scscf.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

mangelwurzel-as.so_SOURCES := mangelwurzel.cpp mangelwurzelplugin.cpp
mangelwurzel-as.so_CPPFLAGS := ${PLUGIN_COMMON_CPPFLAGS} -I../include/mangelwurzel
mangelwurzel-as.so_LDFLAGS := ${PLUGIN_COMMON_LDFLAGS}

VPATH = ../modules/cpp-common/src ../modules/cpp-common/test_utils ../modules/app-servers/test ../modules/gemini/src ../modules/gemini/src/ut ../modules/memento-as/src ../modules/memento-as/src/ut ../modules/memento-as/modules/memento-common/src mangelwurzel mangelwurzel/ut ut

# Use valgrind suppression file for UT
sprout_test_VALGRIND_ARGS := --suppressions=ut/sprout_test.supp

# Exclude the Bono tests from valgrind unless SLOW is set
sprout_test_VALGRIND_EXCL = $(if ${SLOW},,Stateful*Proxy*Test.*)

include ../build-infra/cpp.mk

# Special extra objects for sprout_test
${BUILD_DIR}/bin/sprout_test : ${sprout_test_OBJECT_DIR}/md5.o

# Build rules for SIPp cryptographic modules
SIPP_DIR := ../modules/sipp
$(sprout_test_OBJECT_DIR)/md5.o : $(SIPP_DIR)/md5.c
	$(CC) $(CPPFLAGS) $(sprout_test_CPPFLAGS) -I$(SIPP_DIR) -c $(SIPP_DIR)/md5.c -o $@
CLEANS += ${sprout_test_OBJECT_DIR}/md5.o

# Alarm definition generation rules
ROOT := $(abspath $(shell pwd)/../)
MODULE_DIR := ${ROOT}/modules
include ../modules/cpp-common/makefiles/alarm-utils.mk

../usr/include/sprout_alarmdefinition.h : $(BUILD_DIR)/bin/alarm_header ../sprout-base.root/usr/share/clearwater/infrastructure/alarms/sprout_alarms.json
	$< -j "../sprout-base.root/usr/share/clearwater/infrastructure/alarms/sprout_alarms.json" -n "sprout"
	mv sprout_alarmdefinition.h $@

CLEANS += ../usr/include/sprout_alarmdefinition.h

# The following files all include the alarm defintion
ALARM_DEFINITION_FILES := ${sprout_test_OBJECT_DIR}/hssconnection_test.o \
                          ${sprout_test_OBJECT_DIR}/enumservice_test.o \
                          ${sprout_OBJECT_DIR}/main.o \
                          ${sprout_scscf.so_OBJECT_DIR}/scscfplugin.o

${ALARM_DEFINITION_FILES} : ../usr/include/sprout_alarmdefinition.h

../usr/include/memento_as_alarmdefinition.h : $(BUILD_DIR)/bin/alarm_header ../memento-as.root/usr/share/clearwater/infrastructure/alarms/memento_as_alarms.json
	$< -j "../memento-as.root/usr/share/clearwater/infrastructure/alarms/memento_as_alarms.json" -n "memento_as"
	mv memento_as_alarmdefinition.h $@
${memento-as.so_OBJECT_DIR}/mementoasplugin.o : ../usr/include/memento_as_alarmdefinition.h
CLEANS += ../usr/include/memento_as_alarmdefinition.h
