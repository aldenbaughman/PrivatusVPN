# Compiler
CXX = g++

# Compiler flags
#CXXFLAGS = -lws2_32

# Target executable
TARGET = main

# For deleting the target
TARGET_DEL = main.exe

# Source files
SRCS = main_files/main.cpp main_files/ClientSecureConnection.cpp main_files/VirtualNetworkInterface.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Default rule to build and run the executable
all: $(TARGET) run

# Rule to link object files into the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) -I"C:/Program Files/OpenSSL-Win64/include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" -l:libssl.lib -l:libcrypto.lib -lws2_32

# Rule to compile .cpp files into .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ -I"C:/Program Files/OpenSSL-Win64/include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" -l:libssl.lib -l:libcrypto.lib

# Rule to run the executable
run: $(TARGET)
	$(TARGET)

# Clean rule to remove generated files
clean:
	del $(TARGET_DEL) $(OBJS)
