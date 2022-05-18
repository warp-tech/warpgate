FROM centos/devtoolset-7-toolchain-centos7
USER root
RUN curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -
RUN yum install -y nodejs java pkgconfig openssl-devel && yum clean all
RUN npm i -g yarn
USER 1001
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH=/opt/app-root/src/.cargo/bin:/opt/rh/devtoolset-7/root/usr/bin:/opt/app-root/src/bin:/opt/app-root/bin:/opt/rh/devtoolset-7/root/usr/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
