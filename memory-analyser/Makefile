# Makefile configuration for memory analysis

# Debug build with full memory analysis
debug: CXXFLAGS += -DMEMORY_ANALYSIS_ENABLED -g -O0
debug: LDFLAGS += -DMEMORY_ANALYSIS_ENABLED
debug: target

# AddressSanitizer build
asan: CXXFLAGS += -fsanitize=address -fno-omit-frame-pointer -g -O1
asan: LDFLAGS += -fsanitize=address
asan: target

# Release build with minimal checks
release: CXXFLAGS += -O3 -DNDEBUG
release: target

target: your_source_files.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)