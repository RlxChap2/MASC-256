BUILD_DIR = build
TARGET = acc_crypto

all:
	cmake -B $(BUILD_DIR) -S .
	cmake --build $(BUILD_DIR)

run:
	cmake --build $(BUILD_DIR)
	./$(BUILD_DIR)/$(TARGET)

debug:
	cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DIR) --config Debug

release:
	cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --config Release

clean:
	cmake -E rm -rf $(BUILD_DIR)

rebuild: clean all