# Compiler
CXX = g++

# Compiler flags
#CXXFLAGS = -lws2_32

# Target executable
TARGET = main

# For deleting the target
TARGET_DEL = main.exe

# Source files
SRCS = main_files/main.cpp main_files/ServerSecureConnection.cpp

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
	$(TARGET)

# Clean rule to remove generated files
clean:
	del $(TARGET_DEL) $(OBJS)
