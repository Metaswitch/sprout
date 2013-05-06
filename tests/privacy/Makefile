all : usr_priv_cfg

usr_priv_cfg : usr_priv_cfg.cpp ../../sprout/xdmconnection.cpp ../../include/xdmconnection.h
	g++ -I../../include/ -I../../usr/include -o usr_priv_cfg usr_priv_cfg.cpp ../../sprout/xdmconnection.cpp ../../sprout/utils.cpp ../../sprout/log.cpp ../../sprout/logger.cpp -L../../usr/lib -Wl,-rpath -Wl,../../usr/lib -lvped `curl-config --libs`
