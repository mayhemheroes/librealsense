FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git libssl-dev libusb-1.0-0-dev libudev-dev pkg-config libgtk-3-dev libglfw3-dev libgl1-mesa-dev libglu1-mesa-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y cmake


COPY . /repo

RUN clang++ /repo/mayhem/fuzz_to_lower.cpp -fsanitize=fuzzer,address -I /repo/include/librealsense2/utilities/string/ -std=c++17 -o /fuzz
RUN clang++ /repo/mayhem/fuzz_to_upper.cpp -fsanitize=fuzzer,address -I /repo/include/librealsense2/utilities/string/ -std=c++17 -o /fuzz2
RUN clang++ /repo/mayhem/fuzz_ascii_hex_string_to_uint.cpp -fsanitize=fuzzer,address -I /repo/include/librealsense2/utilities/string/ -std=c++17 -o /fuzz3
RUN clang++ /repo/mayhem/fuzz_trim_newlines.cpp -fsanitize=fuzzer,address -I /repo/include/librealsense2/utilities/string/ -std=c++17 -o /fuzz4

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_to_lower
COPY --from=builder /fuzz2 /fuzz_to_upper
COPY --from=builder /fuzz3 /fuzz_ascii_hex_string_to_uint
COPY --from=builder /fuzz4 /fuzz_trim_newlines
