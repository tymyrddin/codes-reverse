#include "memory_integration.h"
#include "custom_allocator.h"

class SecureApplication {
public:
    SecureApplication() {
        MEM_INIT();
    }

    ~SecureApplication() {
        MEM_SHUTDOWN();
    }

    void process_data(const char* input, size_t length) {
        // Allocate memory with tracking
        char* buffer = static_cast<char*>(TrackingAllocator::allocate(length + 1));

        // Memory integrity can be verified at any point
        MEM_VERIFY_INTEGRITY();

        // Process data
        strncpy(buffer, input, length);
        buffer[length] = '\0';

        // Critical operation - verify memory before proceeding
        MEM_VERIFY_INTEGRITY();

        // Deallocate with tracking
        TrackingAllocator::deallocate(buffer);
    }
};

int main(int argc, char** argv) {
    SecureApplication app;

    try {
        app.process_data("Important data", 14);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}