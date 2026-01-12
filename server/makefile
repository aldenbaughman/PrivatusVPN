# Compiler
CXX = g++

# Compiler flags
#CXXFLAGS = -lws2_32

# Target executable
TARGET = main

# For deleting the target
TARGET_DEL = main.exe

# Source files
SRCS =  main_files/ServerSecureConnection.cpp main_files/VirtualNetworkInterface.cpp main_files/VPNController.cpp main_files/main.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Default rule to build and run the executable
all: $(TARGET) run

# Rule to link object files into the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) -lssl -lcrypto

# Rule to compile .cpp files into .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ -lssl -lcrypto

# Rule to run the executable
run: $(TARGET)
	sudo ./$(TARGET)

# Clean rule to remove generated files
clean:
	rm $(TARGET_DEL) $(OBJS)
