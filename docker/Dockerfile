FROM debian:bullseye
RUN sed -i 's/deb.debian.org/mirrors.bfsu.edu.cn/g' /etc/apt/sources.list
RUN sed -i 's/security.debian.org/mirrors.bfsu.edu.cn/g' /etc/apt/sources.list
RUN apt update
RUN apt install -y sudo
RUN apt install -y gcc g++ python3-pip
RUN apt install -y ninja-build meson
RUN apt install -y socat iproute2
RUN apt install -y psmisc procps
ENV PATH="${HOME}/.local/bin:${PATH}"
