首先编译库

# x86_64

```sh
export PATH=$PATH:$HOME/strongDNS2/openwrt/openwrt-toolchain-24.10.0-x86-64_gcc-13.3.0_musl.Linux-x86_64/toolchain-x86_64_gcc-13.3.0_musl/bin/
export STAGING_DIR=~/openwrt-x86_64

[ -d libmnl ] || git clone https://git.netfilter.org/libmnl
cd libmnl
./autogen.sh
CFLAGS=-I$HOME/openwrt-x86_64/include LDFLAGS=-L$HOME/openwrt-x86_64/lib ./configure --host=x86_64-openwrt-linux-musl --prefix=$HOME/openwrt-x86_64/
make clean && make -j && make install
cd -

[ -d libnfnetlink ] || git clone https://git.netfilter.org/libnfnetlink
cd libnfnetlink
./autogen.sh
CFLAGS=-I$HOME/openwrt-x86_64/include LDFLAGS=-L$HOME/openwrt-x86_64/lib ./configure --host=x86_64-openwrt-linux-musl --prefix=$HOME/openwrt-x86_64/
make clean && make -j && make install
cd -

[ -d libnetfilter_queue ] || git clone https://git.netfilter.org/libnetfilter_queue
cd libnetfilter_queue
./autogen.sh
CFLAGS=-I$HOME/openwrt-x86_64/include LDFLAGS=-L$HOME/openwrt-x86_64/lib ./configure --host=x86_64-openwrt-linux-musl --prefix=$HOME/openwrt-x86_64/ --disable-html-doc --disable-man-pages
make clean && make -j && make install
cd -
```

# aarch64

```sh
export PATH=$PATH:/home/hrimfaxi/strongDNS2/openwrt/openwrt-toolchain-24.10.0-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl/bin
export STAGING_DIR=~/openwrt-aarch64

[ -d libmnl ] || git clone https://git.netfilter.org/libmnl
cd libmnl
./autogen.sh
CFLAGS=-I$HOME/openwrt-aarch64/include LDFLAGS=-L$HOME/openwrt-aarch64/lib ./configure --host=aarch64-openwrt-linux-musl --prefix=$HOME/openwrt-aarch64/
make clean && make -j && make install
cd -

[ -d libnfnetlink ] || git clone https://git.netfilter.org/libnfnetlink
cd libnfnetlink
./autogen.sh
CFLAGS=-I$HOME/openwrt-aarch64/include LDFLAGS=-L$HOME/openwrt-aarch64/lib ./configure --host=aarch64-openwrt-linux-musl --prefix=$HOME/openwrt-aarch64/
make clean && make -j && make install
cd -

[ -d libnetfilter_queue ] || git clone https://git.netfilter.org/libnetfilter_queue
cd libnetfilter_queue
./autogen.sh
CFLAGS=-I$HOME/openwrt-aarch64/include LDFLAGS=-L$HOME/openwrt-aarch64/lib ./configure --host=aarch64-openwrt-linux-musl --prefix=$HOME/openwrt-aarch64/ --disable-html-doc --disable-man-pages
make clean && make -j && make install
cd -
```

# mipsel

```sh
export PATH=$PATH:$HOME/strongDNS2/openwrt/openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
export STAGING_DIR=~/openwrt-mipsel

[ -d libmnl ] || git clone https://git.netfilter.org/libmnl
cd libmnl
./autogen.sh
CFLAGS=-I$HOME/openwrt-mipsel/include LDFLAGS=-L$HOME/openwrt-mipsel/lib ./configure --host=mipsel-openwrt-linux-musl --prefix=$HOME/openwrt-mipsel/
make clean && make -j && make install
cd -

[ -d libnfnetlink ] || git clone https://git.netfilter.org/libnfnetlink
cd libnfnetlink
./autogen.sh
CFLAGS=-I$HOME/openwrt-mipsel/include LDFLAGS=-L$HOME/openwrt-mipsel/lib ./configure --host=mipsel-openwrt-linux-musl --prefix=$HOME/openwrt-mipsel/
make clean && make -j && make install
cd -

[ -d libnetfilter_queue ] || git clone https://git.netfilter.org/libnetfilter_queue
cd libnetfilter_queue
./autogen.sh
CFLAGS=-I$HOME/openwrt-mipsel/include LDFLAGS=-L$HOME/openwrt-mipsel/lib ./configure --host=mipsel-openwrt-linux-musl --prefix=$HOME/openwrt-mipsel/ --disable-html-doc --disable-man-pages
make clean && make -j && make install
cd -

然后，编译可执行文件

`openwrt/x86_64`
```sh
cd ~/strongDNS2
rm -f CMakeCache.txt
mkdir -p build-x86_64
cd build-x86_64
cmake -DCMAKE_TOOLCHAIN_FILE=./toolchains/openwrt-x86_64.cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=output/usr ..
make clean all
make install
```

`openwrt/aarch64`
```sh
cd ~/strongDNS2
rm -f CMakeCache.txt
mkdir -p build-aarch64
cd build-aarch64
cmake -DCMAKE_TOOLCHAIN_FILE=./toolchains/openwrt-aarch64.cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=output/usr ..
make clean all
make install
```

`openwrt/mipsel`:
```sh
cd ~/strongDNS2
rm -f CMakeCache.txt
mkdir -p build-mipsel
cd build-mipsel
cmake -DCMAKE_TOOLCHAIN_FILE=./toolchains/openwrt-mipsel.cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=output/usr ..
make clean all
make install
```

编译结果在`output`目录里。
