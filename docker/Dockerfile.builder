FROM centos/devtoolset-7-toolchain-centos7
USER root
RUN yum install -y pkgconfig openssl-devel && yum clean all
USER 1001
