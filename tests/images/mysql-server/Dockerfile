FROM mariadb:10.8

ENV MYSQL_DATABASE=db
ENV MYSQL_ROOT_PASSWORD=123

ADD init.sql /docker-entrypoint-initdb.d
