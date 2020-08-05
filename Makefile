
CXXFLAGS=-std=c++17 -g
LDFLAGS=-lfmt

all: eh_tool

eh_tool.o: eh_tool.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $< 
eh_tool: eh_tool.o
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

test: eh_tool
	./eh_tool ../mongod
