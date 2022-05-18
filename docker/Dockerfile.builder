FROM centos/devtoolset-7-toolchain-centos7
USER root
RUN curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -
RUN yum install -y nodejs java pkgconfig openssl-devel && yum clean all
RUN npm i -g yarn
USER 1001
