# === Compiler and flags ===
CXX = g++
CXXFLAGS = -std=c++17 -O2

# === GMP paths ===
GMP_INC = /opt/homebrew/Cellar/gmp/6.3.0/include
GMP_LIB = /opt/homebrew/Cellar/gmp/6.3.0/lib

INCLUDES = -I$(GMP_INC)
LDFLAGS  = -L$(GMP_LIB)
LDLIBS   = -lgmp -lgmpxx

# === Source files ===
SRCS = run_rsa.cpp  gen_rsa_key.cpp  gen_plaintext.cpp  rsa_encrypt.cpp  rsa_decrypt.cpp
OBJS = $(SRCS:.cpp=.o)
# BINS = $(SRCS:.cpp=)
# # TARGET = run_rsa  gen_rsa_key  gen_plaintext  rsa_encrypt  rsa_decrypt

# # === Build rules ===

# all: $(BINS)

# $(BINS): $(OBJS)
# 	$(CXX) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

# %.o: %.cpp
# 	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# clean:
# 	rm -f $(OBJS) $(TARGET)

TARGETS = run_rsa gen_rsa_key gen_plaintext rsa_encrypt rsa_decrypt

# 每个可执行文件的依赖 cpp 文件（可根据实际拆分）
run_rsa: run_rsa.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LDLIBS)

gen_rsa_key: gen_rsa_key.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LDLIBS)

gen_plaintext: gen_plaintext.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LDLIBS)

rsa_encrypt: rsa_encrypt.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LDLIBS)

rsa_decrypt: rsa_decrypt.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# === Clean rule ===
clean:
	rm -f $(TARGETS) *.o