FROM postgres:17.0

ENV POSTGRES_DB=db
ENV POSTGRES_USER=user
ENV POSTGRES_PASSWORD=123

ADD init.sql /docker-entrypoint-initdb.d
