# SubSonicEnum
A CUDA-powered DNS subdomain enumerator that tears through subdomains with 1980s grit. Built for speed, precision, and zero fluff. Think neon-lit cyberpunk and raw punk attitude.

## Features
- **GPU-Charged**: NVIDIA CUDA for lightning-fast subdomain generation.
- **DNS Precision**: Queries Google, Cloudflare, and Quad9 resolvers with wildcard detection.
- **No Nonsense**: Outputs valid subdomains to `results/valid_subdomains.txt`.

## Requirements
- NVIDIA CUDA Toolkit (v12.9 recommended)
- CUDA-capable GPU
- C++17 compiler (e.g., g++)

## Installation
```bash
git clone https://github.com/EdgeOfAssembly/SubSonicEnum.git
cd SubSonicEnum
mkdir build && cd build
cmake ..
make
