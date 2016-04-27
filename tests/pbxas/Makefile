pbxas-plugin.so: pbxas.cpp
	g++ pbxas.cpp -shared -fPIC -o pbxas-plugin.so -I../../include -I../../modules/rapidjson/include -I../../modules/cpp-common/include -I../../usr/include/ -std=c++11

clean:
	rm pbxas-plugin.so
.PHONY: clean
