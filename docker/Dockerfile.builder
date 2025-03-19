FROM centos/devtoolset-7-toolchain-centos7
USER root
RUN curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -
RUN yum install -y nodejs java pkgconfig openssl-devel perl-IPC-Cmd && yum clean all
USER 1001
ENV PATH=/opt/app-root/src/.cargo/bin:/opt/rh/devtoolset-7/root/usr/bin:/opt/app-root/src/bin:/opt/app-root/bin:/opt/rh/devtoolset-7/root/usr/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
