
CXXFLAGS=-std=c++17 -g

all: eh_tool

eh_tool:

test: eh_tool
	./eh_tool ../mongod
